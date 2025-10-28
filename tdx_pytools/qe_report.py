# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# QE Report structures - Quoting Enclave report data structures and parsing.

import struct
from dataclasses import dataclass, fields
from typing import ClassVar, Optional

from . import tdx_logging
from .certs import PCKCertChain
from .ecdsa import AttestationKeyType, EcdsaSignature

# Get logger for this module
logger = tdx_logging.get_logger(__name__)


@dataclass
class EnclaveReportBody:
    """
    Represents an SGX Enclave Report body (384 bytes).

    Contains SGX enclave measurements, attributes, and report data
    as specified in the Intel SGX specification. Used for QE reports
    in TDX quote verification.

    Based on Intel SGX specification - used for QE reports
    """

    cpu_svn: bytes  # CPU Security Version Number (16 bytes)
    misc_select: bytes  # Miscellaneous select (4 bytes)
    reserved_1: bytes  # Reserved (28 bytes)
    attributes: bytes  # Enclave attributes (16 bytes)
    mr_enclave: bytes  # Measurement of enclave (32 bytes)
    reserved_2: bytes  # Reserved (32 bytes)
    mr_signer: bytes  # Measurement of signer (32 bytes)
    reserved_3: bytes  # Reserved (32 bytes)
    config_id: bytes  # Configuration ID (64 bytes)
    isv_prod_id: int  # ISV product ID (2 bytes)
    isv_svn: int  # ISV security version number (2 bytes)
    config_svn: int  # Configuration SVN (2 bytes)
    reserved_4: bytes  # Reserved (42 bytes)
    isv_family_id: bytes  # ISV family ID (16 bytes)
    report_data: bytes  # Report data (64 bytes)

    format_string: ClassVar[str] = (
        "<"
        "16s"  # cpu_svn: [u8; 16]
        "4s"  # misc_select: [u8; 4]
        "28s"  # reserved_1: [u8; 28]
        "16s"  # attributes: [u8; 16]
        "32s"  # mr_enclave: [u8; 32]
        "32s"  # reserved_2: [u8; 32]
        "32s"  # mr_signer: [u8; 32]
        "32s"  # reserved_3: [u8; 32]
        "64s"  # config_id: [u8; 64]
        "H"  # isv_prod_id: u16
        "H"  # isv_svn: u16
        "H"  # config_svn: u16
        "42s"  # reserved_4: [u8; 42]
        "16s"  # isv_family_id: [u8; 16]
        "64s"  # report_data: [u8; 64]
    )

    @classmethod
    def unpack(cls, binary_data: bytes, debug: bool = False) -> "EnclaveReportBody":
        """
        Create an EnclaveReportBody instance from binary data.

        Args:
            binary_data: Binary data containing the enclave report body (must be 384 bytes)
            debug: If True, print debug information during unpacking

        Returns:
            EnclaveReportBody: Parsed enclave report body instance

        Raises:
            ValueError: If binary_data is not exactly 384 bytes
        """
        if len(binary_data) != 384:
            raise ValueError(
                f"Enclave report body must be exactly 384 bytes, got {len(binary_data)}"
            )

        # Unpack the binary data using the format string
        unpacked = struct.unpack(cls.format_string, binary_data)

        # Print unpacked values for debugging
        if debug:
            field_names = [f.name for f in fields(cls)]
            for i, (value, field_name) in enumerate(zip(unpacked, field_names)):
                logger.debug(f"Index {i}: {value} - {field_name}")
                if isinstance(value, bytes):
                    logger.debug(f"  Hex: {value.hex()}")

        return cls(
            cpu_svn=unpacked[0],
            misc_select=unpacked[1],
            reserved_1=unpacked[2],
            attributes=unpacked[3],
            mr_enclave=unpacked[4],
            reserved_2=unpacked[5],
            mr_signer=unpacked[6],
            reserved_3=unpacked[7],
            config_id=unpacked[8],
            isv_prod_id=unpacked[9],
            isv_svn=unpacked[10],
            config_svn=unpacked[11],
            reserved_4=unpacked[12],
            isv_family_id=unpacked[13],
            report_data=unpacked[14],
        )

    def to_bytes(self) -> bytes:
        """
        Convert the EnclaveReportBody to its binary representation.

        Serializes all fields into a 384-byte binary format as specified
        in the Intel SGX specification.

        Returns:
            Binary representation of the EnclaveReportBody (384 bytes)

        Raises:
            struct.error: If field values cannot be packed
        """
        return struct.pack(
            self.format_string,
            self.cpu_svn,
            self.misc_select,
            self.reserved_1,
            self.attributes,
            self.mr_enclave,
            self.reserved_2,
            self.mr_signer,
            self.reserved_3,
            self.config_id,
            self.isv_prod_id,
            self.isv_svn,
            self.config_svn,
            self.reserved_4,
            self.isv_family_id,
            self.report_data,
        )

    def print_details(self) -> None:
        """
        Print a detailed representation of the EnclaveReportBody.

        Displays all fields of the enclave report body in a human-readable
        format for debugging and analysis purposes.

        Raises:
            AttributeError: If report body fields are malformed
        """
        logger.info("\n=== Enclave Report Body ===")
        logger.info(f"CPU SVN:                     {self.cpu_svn.hex()}")
        logger.info(f"Misc Select:                 {self.misc_select.hex()}")
        logger.info(f"Attributes:                  {self.attributes.hex()}")
        logger.info(f"MR Enclave:                  {self.mr_enclave.hex()}")
        logger.info(f"MR Signer:                   {self.mr_signer.hex()}")
        logger.info(f"Config ID:                   {self.config_id.hex()}")
        logger.info(f"ISV Product ID:              {self.isv_prod_id}")
        logger.info(f"ISV SVN:                     {self.isv_svn}")
        logger.info(f"Config SVN:                  {self.config_svn}")
        logger.info(f"ISV Family ID:               {self.isv_family_id.hex()}")
        logger.info(f"Report Data:                 {self.report_data.hex()}")


@dataclass
class QeReportCertificationData:
    """
    QeReportCertificationData
    Description: Represents the QE Report certification data structure
    Based on Intel TDX specification
    """

    qe_report: EnclaveReportBody  # QE Report (384 bytes) - parsed enclave report
    qe_report_signature: EcdsaSignature  # QE Report Signature (ECDSA signature)
    qe_authentication_data_size: int  # QE Authentication Data Size (2 bytes)
    qe_authentication_data: bytes  # QE Authentication Data (variable length)
    qe_certification_data_type: int  # QE Certification Data Type (2 bytes)
    qe_certification_data_size: int  # QE Certification Data Size (4 bytes)
    qe_certification_data: bytes  # QE Certification Data (variable length)
    pck_cert_chain: Optional[
        "PCKCertChain"
    ] = None  # Parsed certificate chain if available

    @classmethod
    def unpack(
        cls,
        binary_data: bytes,
        att_key_type: AttestationKeyType,
        debug: bool = False,
    ) -> "QeReportCertificationData":
        """
        Create a QeReportCertificationData instance from binary data.

        Parses binary data containing QE report, signature, and certificate
        chain information for quote verification.

        Args:
            binary_data: Binary data containing the QE report certification data
            att_key_type: The attestation key type from the quote header
            debug: If True, print debug information during unpacking

        Returns:
            QeReportCertificationData instance with parsed data

        Raises:
            ValueError: If binary data is insufficient or malformed
        """
        if len(binary_data) < 384 + 64 + 2:
            raise ValueError(
                f"Insufficient data for QE report certification: expected at least {384 + 64 + 2} bytes, got {len(binary_data)}"
            )

        # Parse fixed-size fields
        qe_report_bytes = binary_data[:384]
        qe_report = EnclaveReportBody.unpack(qe_report_bytes, debug=debug)
        qe_report_signature_bytes = binary_data[384 : 384 + 64]
        # Parse ECDSA signature using the key type from header
        qe_report_signature = EcdsaSignature.from_bytes(
            qe_report_signature_bytes, att_key_type
        )
        qe_authentication_data_size = struct.unpack(
            "<H", binary_data[384 + 64 : 384 + 64 + 2]
        )[0]

        # Validate authentication data size
        auth_data_end = 384 + 64 + 2 + qe_authentication_data_size
        if (
            len(binary_data) < auth_data_end + 6
        ):  # Need at least 2 bytes for type + 4 bytes for size for following cert data
            raise ValueError(
                f"Insufficient data for authentication data: expected at least {auth_data_end + 6} bytes, got {len(binary_data)}"
            )

        qe_authentication_data = binary_data[384 + 64 + 2 : auth_data_end]
        qe_certification_data_type = struct.unpack(
            "<H", binary_data[auth_data_end : auth_data_end + 2]
        )[0]
        qe_certification_data_size = struct.unpack(
            "<I", binary_data[auth_data_end + 2 : auth_data_end + 6]
        )[0]

        # Validate certification data size
        cert_data_end = auth_data_end + 6 + qe_certification_data_size
        if len(binary_data) < cert_data_end:
            raise ValueError(
                f"Insufficient data for certification data: expected at least {cert_data_end} bytes, got {len(binary_data)}"
            )

        qe_certification_data = binary_data[auth_data_end + 6 : cert_data_end]

        if debug:
            print(f"Authentication Data Size: {qe_authentication_data_size} bytes")
            print(
                f"QE Report Certification Data Type: {qe_certification_data_type}"
            )  # Probably type 5 but not a requirement
            print(
                f"QE Report Certification Data Size: {qe_certification_data_size} bytes"
            )

        # Parse PCK certificate chain if available, from type 4 and 5 certification data
        # Type 5 is expected to contain a full chain, type 4 is a single PCK leaf certificate
        pck_cert_chain = None
        if qe_certification_data_type == 5:
            pck_cert_chain = PCKCertChain.from_certification_data(qe_certification_data)
            if debug:
                print(
                    f"Loaded {len(pck_cert_chain.certificates)} certificates from QE certification data"
                )
                pck_cert_chain.print_chain_details()
                ##TODO THE FOLLOWING IS FOR TESTING, ACTUAL VERIFICATION WILL BE DONE LATER
                ##TODO Type 4 will need to download the rest of the chain
                # Verify certificate chain integrity
                chain_valid = pck_cert_chain.verify_chain()
                print(
                    f"Certificate chain verification: {'VALID' if chain_valid else 'INVALID'}"
                )

                # Verify certificate dates
                from .certs import validate_certificate_dates

                for i, cert in enumerate(pck_cert_chain.certificates):
                    cert_type = (
                        "PCK"
                        if i == 0
                        else "Root"
                        if i == len(pck_cert_chain.certificates) - 1
                        else "Intermediate"
                    )
                    date_valid = validate_certificate_dates(cert)
                    print(
                        f"{cert_type} certificate date validation: {'VALID' if date_valid else 'EXPIRED/INVALID'}"
                    )
                    if not date_valid:
                        print(f"  Valid from: {cert.not_valid_before_utc}")
                        print(f"  Valid to:   {cert.not_valid_after_utc}")
        elif qe_certification_data_type == 4:
            pck_cert_chain = PCKCertChain.from_certification_data(qe_certification_data)
            if len(pck_cert_chain.certificates) != 1:
                raise ValueError(
                    "QE certification data type 4 should only contain a single PCK certificate"
                )
            else:
                if debug:
                    print(
                        "QE certification data type 4 contains a single PCK certificate"
                    )
                    pck_cert_chain.print_chain_details()

        return cls(
            qe_report=qe_report,
            qe_report_signature=qe_report_signature,
            qe_authentication_data_size=qe_authentication_data_size,
            qe_authentication_data=qe_authentication_data,
            qe_certification_data_type=qe_certification_data_type,
            qe_certification_data_size=qe_certification_data_size,
            qe_certification_data=qe_certification_data,
            pck_cert_chain=pck_cert_chain,
        )

    def to_bytes(self) -> bytes:
        """
        Convert the QeReportCertificationData to its binary representation.

        Serializes all fields including QE report, signature, and certificate
        chain data into binary format for quote generation.

        Returns:
            Binary representation of the QeReportCertificationData

        Raises:
            struct.error: If field values cannot be packed
        """
        result = self.qe_report.to_bytes()
        result += self.qe_report_signature.to_bytes()
        result += struct.pack("<H", self.qe_authentication_data_size)
        result += self.qe_authentication_data
        result += struct.pack("<H", self.qe_certification_data_type)
        result += struct.pack("<I", self.qe_certification_data_size)
        result += self.qe_certification_data
        return result
