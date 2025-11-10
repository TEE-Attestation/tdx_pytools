# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Certificate handling - X.509 certificate parsing and verification for Intel SGX/TDX.

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.codec.der import decoder
from pyasn1.type import univ

from . import tdx_logging

# Get logger for this module
logger = tdx_logging.get_logger(__name__)


class SgxOid(Enum):
    """Intel SGX Certificate Extension OIDs"""

    # Main SGX Extensions
    SGXExtensions = ObjectIdentifier("1.2.840.113741.1.13.1")
    PPID = ObjectIdentifier("1.2.840.113741.1.13.1.1")
    TCB = ObjectIdentifier("1.2.840.113741.1.13.1.2")

    # TCB Components (SGX TCB Comp01-16 SVN)
    SGX_TCB_COMP01_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.1")
    SGX_TCB_COMP02_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.2")
    SGX_TCB_COMP03_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.3")
    SGX_TCB_COMP04_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.4")
    SGX_TCB_COMP05_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.5")
    SGX_TCB_COMP06_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.6")
    SGX_TCB_COMP07_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.7")
    SGX_TCB_COMP08_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.8")
    SGX_TCB_COMP09_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.9")
    SGX_TCB_COMP10_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.10")
    SGX_TCB_COMP11_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.11")
    SGX_TCB_COMP12_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.12")
    SGX_TCB_COMP13_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.13")
    SGX_TCB_COMP14_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.14")
    SGX_TCB_COMP15_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.15")
    SGX_TCB_COMP16_SVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.16")

    # PCE and CPU SVN
    PCESVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.17")
    CPUSVN = ObjectIdentifier("1.2.840.113741.1.13.1.2.18")

    # Platform Information
    PCE_ID = ObjectIdentifier("1.2.840.113741.1.13.1.3")
    FMSPC = ObjectIdentifier("1.2.840.113741.1.13.1.4")
    SGX_TYPE = ObjectIdentifier("1.2.840.113741.1.13.1.5")
    PLATFORM_INSTANCE_ID = ObjectIdentifier("1.2.840.113741.1.13.1.6")

    # Configuration (optional, platform-specific)
    CONFIGURATION = ObjectIdentifier("1.2.840.113741.1.13.1.7")
    DYNAMIC_PLATFORM = ObjectIdentifier("1.2.840.113741.1.13.1.7.1")
    CACHED_KEYS = ObjectIdentifier("1.2.840.113741.1.13.1.7.2")
    SMT_ENABLED = ObjectIdentifier("1.2.840.113741.1.13.1.7.3")

    def __str__(self):
        return self.value.dotted_string


@dataclass
class PCKCertChain:
    """
    PCKCertChain
    Description: Represents a PCK (Provisioning Certification Key) certificate chain
    Used to store and manage certificates from TDX QE certification data
    """

    pck_leaf_cert: x509.Certificate  # The PCK leaf certificate
    pck_cert_chain: Optional[
        List[x509.Certificate]
    ] = None  # List of certificates in the chain (Intermediate and Root)

    @classmethod
    def from_certification_data(cls, cert_data: bytes) -> "PCKCertChain":
        """
        Create a PCKCertChain from QE certification data.

        Parses PEM-encoded X.509 certificates from QE certification data
        and organizes them into a certificate chain structure.

        Args:
            cert_data: Raw certification data from QE report (PEM format)

        Returns:
            PCKCertChain: Instance containing parsed certificates

        Raises:
            ValueError: If no valid certificates found in the provided data
        """
        certificates = x509.load_pem_x509_certificates(cert_data)
        if len(certificates) > 1:
            return cls(pck_leaf_cert=certificates[0], pck_cert_chain=certificates[1:])
        elif len(certificates) == 1:
            return cls(pck_leaf_cert=certificates[0])
        else:
            raise ValueError("No valid certificates found in the provided data")

    @property
    def pck_cert(self) -> x509.Certificate:
        """
        Get the PCK (Platform Certification Key) certificate.

        Returns:
            x509.Certificate: The PCK leaf certificate
        """
        return self.pck_leaf_cert

    @property
    def cert_chain(self) -> Optional[List[x509.Certificate]]:
        """
        Get the certificate chain (intermediate and root certificates).

        Returns:
            Optional list of intermediate certificates, None if no chain available
        """
        return self.pck_cert_chain

    @property
    def certificates(self) -> List[x509.Certificate]:
        """
        Get all certificates in the chain as a single list.

        Combines the PCK leaf certificate with the certificate chain
        to provide a complete view of all certificates.

        Returns:
            List containing all certificates (leaf + chain)
        """
        all_certs = [self.pck_leaf_cert]
        if self.pck_cert_chain:
            all_certs.extend(self.pck_cert_chain)
        return all_certs

    def verify_chain(self) -> bool:
        """
        Verify the certificate chain integrity.

        Validates that each certificate in the chain is properly signed
        by its parent certificate.

        Returns:
            bool: True if chain is valid, False otherwise
        """
        if len(self.certificates) < 2:
            return False

        try:
            # Verify each certificate in the chain against its issuer
            for i in range(len(self.certificates) - 1):
                child_cert = self.certificates[i]
                parent_cert = self.certificates[i + 1]

                # Verify the signature
                parent_public_key = parent_cert.public_key()
                if isinstance(parent_public_key, rsa.RSAPublicKey):
                    from cryptography.hazmat.primitives import padding

                    parent_public_key.verify(
                        child_cert.signature,
                        child_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        hashes.SHA256(),
                    )
                elif isinstance(parent_public_key, ec.EllipticCurvePublicKey):
                    parent_public_key.verify(
                        child_cert.signature,
                        child_cert.tbs_certificate_bytes,
                        ec.ECDSA(hashes.SHA256()),
                    )
                else:
                    return False

            return True
        except Exception:
            return False

    def get_sgx_extensions(self) -> Dict[str, bytes]:
        """
        Extract Intel SGX extensions from the PCK certificate.

        Parses the SGX-specific extensions from the PCK certificate
        and returns them as a dictionary, raising an error if required extensions are missing.

        Returns:
            dict: Dictionary of SGX extension values (keys are SgxOid enum names)
        """
        try:
            sgx_extensions = parse_sgx_extensions(self.pck_cert)
            # Check cert extensions include PPID, TCB, PCEID, FMSPC
            required_oids = ["PPID", "TCB", "PCE_ID", "FMSPC"]
            missing_oids = [oid for oid in required_oids if oid not in sgx_extensions]
            if missing_oids:
                raise ValueError(
                    f"Missing required SGX extensions in PCK certificate: {', '.join(missing_oids)}"
                )
            return sgx_extensions
        except Exception as e:
            logger.error(f"Error extracting SGX extensions: {e}")
            raise ValueError("Failed to extract SGX extensions from PCK certificate")

    def print_chain_details(self) -> None:
        """
        Print detailed information about all certificates in the chain.

        Displays comprehensive information about each certificate in the
        PCK certificate chain including type, subject, and validity.

        Raises:
            AttributeError: If certificates are malformed
        """
        print(f"\n=== PCK Certificate Chain ===")
        print(f"Total certificates: {len(self.certificates)}")

        for i, cert in enumerate(self.certificates):
            cert_type = (
                "PCK"
                if i == 0
                else "Root"
                if i == len(self.certificates) - 1
                else "Intermediate"
            )
            print(f"\n--- Certificate {i + 1} ({cert_type}) ---")
            print_certificate_details(cert)

    def export_chain(self, output_path: str, format: str = "pem") -> None:
        """
        Export this certificate chain to a file.

        Saves all certificates in the chain to a single file in the
        specified format (PEM or DER).

        Args:
            output_path: Path to output file
            format: Export format ("pem" or "der")

        Raises:
            ValueError: If format is not supported
            OSError: If unable to write to output file
        """
        export_certificates(self.certificates, output_path, format)


def print_certificate_details(cert: x509.Certificate) -> None:
    """
    Print detailed information about a certificate.

    Displays certificate subject, issuer, serial number, validity dates,
    and other important certificate metadata.

    Args:
        cert: Certificate to print details for

    Raises:
        AttributeError: If certificate is malformed or missing required fields
    """
    print(f"Subject:             {cert.subject}")
    print(f"Issuer:              {cert.issuer}")
    print(f"Serial Number:       {cert.serial_number}")
    print(f"Valid From:          {cert.not_valid_before_utc}")
    print(f"Valid To:            {cert.not_valid_after_utc}")
    print(f"Signature Algorithm: {cert.signature_algorithm_oid._name}")

    # Print public key information
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        print(f"Public Key:          RSA ({public_key.key_size} bits)")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        print(f"Public Key:          EC ({public_key.curve.name})")
    else:
        print(f"Public Key:          {type(public_key).__name__}")


def get_certificate_extension(cert: x509.Certificate, oid: str) -> Optional[bytes]:
    """
    Get the value of a specific extension from a certificate.

    Extracts extension data by OID string, returning the raw bytes
    of the extension value if found.

    Args:
        cert: Certificate to extract extension from
        oid: Object Identifier string of the extension

    Returns:
        Extension value as bytes if found, None otherwise

    Raises:
        ValueError: If OID string is malformed
    """
    try:
        extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(oid))
        return extension.value
    except x509.ExtensionNotFound:
        return None


def parse_sgx_extensions(cert: x509.Certificate) -> dict:
    """
    Parse Intel SGX extensions from a PCK certificate.

    Extracts SGX-specific extensions including PPID, TCB components,
    FMSPC, PCE_ID, and other platform-specific information.

    Args:
        cert: PCK certificate to parse

    Returns:
        dict: Dictionary of parsed SGX extension values (keys are SgxOid enum names)

    Raises:
        ValueError: If SGX extensions cannot be parsed
    """
    try:
        # Get the main SGX Extensions field
        sgx_ext = cert.extensions.get_extension_for_oid(SgxOid.SGXExtensions.value)
        # The value is UnrecognizedExtension, so get raw bytes
        sgx_data = sgx_ext.value.value

        logger.debug(f"SGX extension data length: {len(sgx_data)} bytes")

        # Parse the ASN.1 structure without specifying schema (auto-detect)
        decoded, _ = decoder.decode(sgx_data)

        # Create a mapping from OID strings to enum names
        oid_to_name = {}
        for sgx_oid in SgxOid:
            oid_to_name[sgx_oid.value.dotted_string] = sgx_oid.name

        extensions = {}

        # Iterate through the top-level sequence
        for item in decoded:
            # Each item should be a sequence with [OID, Value]
            if len(item) >= 2:
                oid_component = item[0]
                value_component = item[1]

                # Get OID as string
                oid_str = str(oid_component)

                # Get the enum name for this OID, or use the OID string if not found
                key_name = oid_to_name.get(oid_str, oid_str)

                logger.debug(f"Found SGX sub-extension: {oid_str} ({key_name})")

                # Parse value based on its type
                if isinstance(value_component, univ.OctetString):
                    # It's an octet string, extract bytes
                    extensions[key_name] = bytes(value_component)
                    logger.debug(
                        f"  Type: OctetString, Length: {len(bytes(value_component))} bytes, Hex: {bytes(value_component).hex()}"
                    )
                elif isinstance(value_component, univ.Integer):
                    # It's an integer
                    extensions[key_name] = int(value_component)
                    logger.debug(f"  Type: Integer, Value: {int(value_component)}")
                elif isinstance(value_component, (univ.Boolean, bool)):
                    # It's a boolean
                    extensions[key_name] = bool(value_component)
                    logger.debug(f"  Type: Boolean, Value: {bool(value_component)}")
                elif isinstance(value_component, (univ.Sequence, univ.SequenceOf)):
                    # It's a sequence (like TCB components)
                    # Store the nested sequence for further parsing if needed
                    extensions[key_name] = value_component
                    logger.debug(
                        f"  Type: Sequence/SequenceOf, Length: {len(value_component)}"
                    )

                    # If this is the TCB sequence, parse its components
                    if oid_str == SgxOid.TCB.value.dotted_string:
                        logger.debug(f"  Parsing TCB components...")
                        tcb_dict = {}
                        for tcb_item in value_component:
                            if len(tcb_item) >= 2:
                                tcb_oid_str = str(tcb_item[0])
                                tcb_key_name = oid_to_name.get(tcb_oid_str, tcb_oid_str)

                                # Parse value based on type
                                if isinstance(tcb_item[1], univ.Integer):
                                    tcb_value = int(tcb_item[1])
                                elif isinstance(tcb_item[1], univ.OctetString):
                                    tcb_value = bytes(tcb_item[1])
                                else:
                                    tcb_value = tcb_item[1]

                                tcb_dict[tcb_key_name] = tcb_value

                                # Format debug output based on type
                                if isinstance(tcb_value, bytes):
                                    logger.debug(
                                        f"    TCB Component: {tcb_oid_str} ({tcb_key_name}) = {tcb_value.hex()}"
                                    )
                                else:
                                    logger.debug(
                                        f"    TCB Component: {tcb_oid_str} ({tcb_key_name}) = {tcb_value}"
                                    )
                        parsed_key = f"{key_name}_parsed"
                        extensions[parsed_key] = tcb_dict
                        logger.debug(
                            f"  Created {parsed_key} with {len(tcb_dict)} components"
                        )
                else:
                    # Unknown type, store as-is
                    extensions[key_name] = value_component
                    logger.debug(f"  Type: {type(value_component).__name__}")

        logger.debug(f"Parsed {len(extensions)} SGX sub-extensions")
        return extensions

    except x509.ExtensionNotFound:
        logger.warning("SGX Extensions not found in certificate")
        return {}
    except Exception as e:
        logger.error(f"Error parsing SGX extensions: {e}")
        import traceback

        logger.debug(traceback.format_exc())
        return {}


def export_certificates(
    certificates: List[x509.Certificate], output_path: str, format: str = "pem"
) -> None:
    """
    Export a list of certificates to a file.

    Saves certificates in the specified format (PEM or DER) to a file,
    useful for certificate chain storage or analysis.

    Args:
        certificates: List of certificates to export
        output_path: Path to output file
        format: Export format ("pem" or "der")

    Raises:
        ValueError: If format is not supported
        OSError: If unable to write to output file
    """
    if format.lower() == "pem":
        encoding = serialization.Encoding.PEM
    elif format.lower() == "der":
        encoding = serialization.Encoding.DER
    else:
        raise ValueError("Format must be 'pem' or 'der'")

    with open(output_path, "wb") as f:
        for cert in certificates:
            f.write(cert.public_bytes(encoding))
            if format.lower() == "pem":
                f.write(b"\n")


def validate_certificate_dates(cert: x509.Certificate) -> bool:
    """
    Check if a certificate is currently valid (not expired).

    Validates that the current time is within the certificate's
    validity period.

    Args:
        cert: Certificate to validate

    Returns:
        bool: True if certificate is valid, False otherwise
    """
    now = datetime.now(timezone.utc)
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def verify_certificate(cert: x509.Certificate, key) -> bool:
    """
    Verify a certificate's signature using a public key.

    Validates that the certificate was signed by the provided key,
    supporting both EC and RSA signature algorithms.

    Args:
        cert: Certificate object to verify
        key: Public key to use for verification

    Returns:
        bool: True if verification succeeds, False otherwise
    """
    try:
        # Check if the key is an EC or RSA key and verify accordingly
        if isinstance(key, ec.EllipticCurvePublicKey):
            # For EC keys, use ECDSA with the hash algorithm from the certificate
            key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        elif isinstance(key, rsa.RSAPublicKey):
            # For RSA keys, use the padding and hash algorithm from the certificate
            from cryptography.hazmat.primitives.asymmetric import padding

            key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            logger.error(f"Unsupported key type: {type(key).__name__}")
            return False
    except InvalidSignature:
        logger.error("Invalid certificate signature.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying certificate: {str(e)}")
        return False
    return True


def verify_crl(crl: x509.CertificateRevocationList, key) -> bool:
    """
    Verify a certificate revocation list's signature using a public key.

    Validates that the CRL was signed by the given public key, ensuring
    the CRL's authenticity and integrity.

    Args:
        crl: Certificate revocation list to verify
        key: Public key to use for verification

    Returns:
        True if verification succeeds, False otherwise

    Raises:
        Exception: For verification errors (caught internally)
    """
    try:
        key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            ec.ECDSA(crl.signature_hash_algorithm),
        )
    except InvalidSignature:
        logger.error("Invalid CRL signature.")
        return False
    except Exception as e:
        logger.error(f"Unexpected error verifying CRL: {str(e)}")
        return False
    return True


def check_certificate_against_crl(
    cert: x509.Certificate, crl: x509.CertificateRevocationList
) -> bool:
    """
    Check if a certificate is revoked using a Certificate Revocation List.

    Validates that the certificate has not been revoked by checking its
    serial number against the CRL entries.

    Args:
        cert: Certificate to check for revocation
        crl: Certificate Revocation List to check against

    Returns:
        True if certificate is NOT revoked, False if it is revoked

    Raises:
        ValueError: If CRL is expired or malformed
    """
    # Check CRL is current
    current_time = datetime.now(timezone.utc)
    if crl.next_update_utc and current_time > crl.next_update_utc:
        logger.error(f"CRL is expired (next update field is {crl.next_update_utc})")
        return False

    # Get the certificate's serial number
    cert_serial = cert.serial_number

    # Check if the certificate is in the CRL
    try:
        revoked_cert = crl.get_revoked_certificate_by_serial_number(cert_serial)
        if revoked_cert is not None:
            logger.error(
                f"Certificate with serial {cert_serial} is REVOKED. Revocation date: {revoked_cert.revocation_date}"
            )
            try:
                reason_ext = revoked_cert.extensions.get_extension_for_oid(
                    x509.ExtensionOID.CRL_REASON
                )
                logger.error(f"  Revocation reason: {reason_ext.value.reason}")
            except x509.ExtensionNotFound:
                pass
            return False
        else:
            logger.debug(f"Certificate with serial {cert_serial} is NOT revoked.")
            return True
    except Exception as e:
        logger.error(f"Error checking CRL for certificate serial {cert_serial}: {e}")
        return False
