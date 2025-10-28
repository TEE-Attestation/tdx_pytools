# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Fetch utilities - Retrieve certificates and collateral from Intel PCS API.

import argparse
import enum
import json
import os
from typing import List, Optional, Tuple
from urllib.parse import unquote, urljoin

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import tdx_logging

# Get logger for this module
logger = tdx_logging.get_logger(__name__)

# Constants for Intel's TDX certificate infrastructure
INTEL_PCS_BASE_URL = "https://api.trustedservices.intel.com/sgx/certification/v4/"
INTEL_TDX_BASE_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/"
INTEL_PCS_ROOT_CA_BASE_URL = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA"


class CertFormat(enum.Enum):
    """Certificate encoding formats"""

    PEM = "pem"
    DER = "der"


def create_retry_session(
    retries: int = 5,
    backoff_factor: float = 0.1,
    status_forcelist: Tuple[int, ...] = (500, 502, 503, 504),
    timeout: int = 10,
) -> requests.Session:
    """
    Create a requests session with retry logic and SSL verification.

    Configures a session with automatic retries for transient failures
    and proper SSL certificate verification for secure communication
    with Intel's services.

    Args:
        retries: Number of retries for failed requests
        backoff_factor: Backoff factor for retries
        status_forcelist: HTTP status codes to retry on
        timeout: Default timeout for requests

    Returns:
        requests.Session: Configured session object
    """
    session = requests.Session()

    # Configure SSL verification - always enabled for security
    # Try to use certifi's CA bundle if available for better compatibility
    try:
        import certifi

        session.verify = certifi.where()
        logger.debug("Using certifi CA bundle for SSL verification")
    except ImportError:
        # Fall back to default verification
        session.verify = True
        logger.debug("Using system default CA bundle for SSL verification")

    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.timeout = timeout

    # Set User-Agent for Intel PCS API
    session.headers.update(
        {
            "User-Agent": "TDX-PyTools/1.0",
            "Accept": "application/json, application/x-pem-file, application/pkix-crl",
        }
    )

    return session


def validate_fmspc(fmspc: str) -> str:
    """
    Validate and normalize FMSPC format.

    FMSPC (Family-Model-Stepping-Platform-CustomSKU) is a 6-byte identifier
    used to identify platform configurations for TCB Info lookup.

    Args:
        fmspc: FMSPC value as hex string

    Returns:
        str: Normalized FMSPC value (uppercase, 12 characters)

    Raises:
        ValueError: If FMSPC format is invalid
    """
    # Remove any spaces or hyphens
    fmspc = fmspc.replace(" ", "").replace("-", "")

    # Check if it's a valid hex string
    try:
        int(fmspc, 16)
    except ValueError:
        raise ValueError(f"Invalid FMSPC format: {fmspc}. Must be a hex string.")

    # FMSPC should be 12 characters (6 bytes)
    if len(fmspc) != 12:
        raise ValueError(
            f"Invalid FMSPC length: {len(fmspc)}. Expected 12 characters (6 bytes)."
        )

    return fmspc.upper()


def request_tcb_info(fmspc: str, update: str = "standard") -> Tuple[str, str]:
    """
    Fetch TCB Info from Intel PCS.

    Retrieves TCB (Trusted Computing Base) information for the specified
    platform FMSPC, including TCB levels and associated status information.

    Args:
        fmspc: FMSPC value as hex string
        update: Update type ("standard" or "early")

    Returns:
        Tuple containing:
        - str: Raw TCB info response text (JSON)
        - str: TCB Info issuer certificate chain

    Raises:
        Exception: If unable to fetch TCB Info
    """
    url = urljoin(INTEL_TDX_BASE_URL, f"tcb?fmspc={fmspc}&update={update}")
    tdx_logging.log_network_request(url, "GET")

    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    if response.status_code == 200:
        tdx_logging.log_network_request(url, "GET", response.status_code)
        # Return both parsed JSON and raw text for signature verification
        return response.text, response.headers["TCB-Info-Issuer-Chain"]
    else:
        raise Exception(
            f"Unable to fetch TCB Info: {response.status_code} - {response.text}"
        )


def request_qe_identity(update: str) -> Tuple[str, str]:
    """
    Fetch QE Identity from Intel PCS.

    Retrieves Quoting Enclave identity information including measurements
    and certificate chain for QE verification.

    Args:
        update: Update policy ("standard" or "early")

    Returns:
        Tuple containing:
        - str: Raw QE identity response text (JSON)
        - str: Certificate chain string

    Raises:
        Exception: If unable to fetch QE Identity
    """
    url = urljoin(INTEL_TDX_BASE_URL, f"qe/identity?update={update}")
    tdx_logging.log_network_request(url, "GET")

    session = create_retry_session()
    response = session.get(url, timeout=session.timeout)

    if response.status_code == 200:
        tdx_logging.log_network_request(url, "GET", response.status_code)
        # Return both parsed JSON and raw text for signature verification
        return response.text, response.headers["SGX-Enclave-Identity-Issuer-Chain"]
    else:
        raise Exception(
            f"Unable to fetch QE Identity: {response.status_code} - {response.text}"
        )


def request_root_ca_certificate() -> x509.Certificate:
    """
    Fetch Root CA certificate from Intel.

    Retrieves the Intel SGX Root CA certificate used as the root of trust
    for certificate chain verification.

    Returns:
        x509.Certificate: Intel SGX Root CA certificate

    Raises:
        Exception: If unable to fetch the root certificate
    """
    url_pem = INTEL_PCS_ROOT_CA_BASE_URL + ".pem"
    # url_der = INTEL_PCS_ROOT_CA_BASE_URL + ".cer"
    tdx_logging.log_network_request(url_pem, "GET")

    session = create_retry_session()
    response = session.get(url_pem, timeout=session.timeout)

    if response.status_code == 200:
        tdx_logging.log_network_request(url_pem, "GET", response.status_code)
        cert = x509.load_pem_x509_certificate(response.content)
        return cert
    else:
        raise Exception(
            f"Unable to fetch Root CA certificate: {response.status_code} - {response.text}"
        )


def request_pck_crl(ca: str = "platform") -> x509.CertificateRevocationList:
    """
    Fetch PCK CRL from Intel.

    Retrieves the Intel SGX PCK CRL (Platform Certificate Revocation List)
    used for certificate validation.

    Args:
        ca: CA type ("platform" or "processor")

    Returns:
        x509.CertificateRevocationList: PCK CRL

    Raises:
        Exception: If unable to fetch the PCK CRL
    """
    url = urljoin(INTEL_PCS_BASE_URL, f"pckcrl?ca={ca}&encoding=der")
    tdx_logging.log_network_request(url, "GET")

    try:
        session = create_retry_session()
        response = session.get(url, timeout=session.timeout)

        if response.status_code == 200:
            tdx_logging.log_network_request(url, "GET", response.status_code)
            crl = x509.load_der_x509_crl(response.content)
            return crl
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")

    except Exception as e:
        raise Exception(f"Unable to fetch PCK CRL: {e}")


def request_root_ca_crl(root_cert: x509.Certificate) -> x509.CertificateRevocationList:
    """
    Fetch Root CA CRL by extracting CDP URI from the root certificate.

    Extracts the Certificate Revocation List Distribution Point URI from
    the root certificate and fetches the corresponding CRL.

    Args:
        root_cert: Root CA certificate containing CDP extension

    Returns:
        Certificate Revocation List from the CDP URI

    Raises:
        Exception: If CDP URI not found or CRL fetch fails
    """
    # Extract CDP (CRL Distribution Point) URI from the certificate
    try:
        crl_distribution_points = root_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        cdp_value = crl_distribution_points.value

        # Get the first distribution point with a URI
        cdp_uri = None
        for distribution_point in cdp_value:
            if distribution_point.full_name:
                for general_name in distribution_point.full_name:
                    if isinstance(general_name, x509.UniformResourceIdentifier):
                        cdp_uri = general_name.value
                        break
            if cdp_uri:
                break

        if not cdp_uri:
            raise Exception("No CRL Distribution Point URI found in certificate")

        logger.info(f"Extracted CDP URI from certificate: {cdp_uri}")

    except x509.ExtensionNotFound:
        raise Exception(
            "Certificate does not contain CRL Distribution Points extension"
        )
    except Exception as e:
        raise Exception(f"Failed to extract CDP URI from certificate: {e}")

    # Fetch CRL from the CDP URI
    tdx_logging.log_network_request(cdp_uri, "GET")

    try:
        session = create_retry_session()
        response = session.get(cdp_uri, timeout=session.timeout)

        if response.status_code == 200:
            tdx_logging.log_network_request(cdp_uri, "GET", response.status_code)
            # Try to parse as DER or PEM
            try:
                crl = x509.load_der_x509_crl(response.content)
            except:
                try:
                    crl = x509.load_pem_x509_crl(response.content)
                except Exception as parse_error:
                    raise Exception(f"Failed to parse CRL as DER or PEM: {parse_error}")
            logger.info(f"Successfully fetched Root CA CRL from CDP URI")
            return crl
        else:
            raise Exception(f"HTTP {response.status_code}: {response.text}")

    except Exception as e:
        raise Exception(f"Unable to fetch Root CA CRL from CDP URI: {e}")


def write_certificate(
    certs_dir: str, cert_name: str, cert: x509.Certificate, cert_format: CertFormat
) -> None:
    """
    Write a certificate to a file.

    Saves an X.509 certificate to disk in the specified format (PEM or DER).

    Args:
        certs_dir: Directory to write the certificate file
        cert_name: Base name for the certificate file
        cert: X.509 certificate to write
        cert_format: Format to write (PEM or DER)

    Raises:
        OSError: If unable to create directory or write file
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    filename = f"{cert_name.lower()}.{cert_format.value}"
    filepath = os.path.join(certs_dir, filename)

    if cert_format == CertFormat.PEM:
        encoding = serialization.Encoding.PEM
    else:
        encoding = serialization.Encoding.DER

    with open(filepath, "wb") as f:
        f.write(cert.public_bytes(encoding))

    logger.info(f"Saved {cert_name} certificate to {filepath}")


def write_crl(
    certs_dir: str,
    crl_name: str,
    crl: x509.CertificateRevocationList,
    cert_format: CertFormat,
):
    """
    Write a Certificate Revocation List to a file.

    Saves a CRL to disk in the specified format (PEM or DER) for
    certificate validation processes.

    Args:
        certs_dir: Directory to save the CRL file
        crl_name: Base name for the CRL file
        crl: Certificate Revocation List to write
        cert_format: Format to write (PEM or DER)

    Raises:
        OSError: If unable to create directory or write file
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    filename = f"{crl_name.lower()}.{cert_format.value}"
    filepath = os.path.join(certs_dir, filename)

    if cert_format == CertFormat.PEM:
        encoding = serialization.Encoding.PEM
    else:
        encoding = serialization.Encoding.DER

    with open(filepath, "wb") as f:
        f.write(crl.public_bytes(encoding))

    logger.info(f"Saved {crl_name} CRL to {filepath}")


def write_json_data(certs_dir: str, filename: str, data: dict) -> None:
    """
    Write JSON data to a file.

    Saves dictionary data as formatted JSON to the specified directory.

    Args:
        certs_dir: Directory to save the file
        filename: Name of the JSON file
        data: Dictionary data to write as JSON

    Raises:
        OSError: If unable to create directory or write file
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    filepath = os.path.join(certs_dir, filename)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"Saved JSON data to {filepath}")


def fetch_tcb_info(
    fmspc: str, certs_dir: str, update: str = "standard"
) -> Tuple[str, str]:
    """
    Fetch and save TCB Info, or load from existing files if they exist.

    Retrieves TCB (Trusted Computing Base) information and certificate chain
    for the specified FMSPC value, caching results locally.

    Args:
        fmspc: FMSPC (Family-Model-Stepping-Platform-Customer) value
        certs_dir: Directory to save TCB info files
        update: Update policy ("standard" or "early")

    Returns:
        Tuple of (TCB Info JSON string, TCB Info certificate chain PEM)

    Raises:
        Exception: If unable to fetch or load TCB info
    """
    tcb_info_file = os.path.join(certs_dir, f"{fmspc}_{update}_tcb_info.json")
    tcb_certs_file = os.path.join(
        certs_dir, f"{fmspc}_{update}_tcb_info_issuer_chain.pem"
    )

    # Check if files already exist
    if os.path.exists(tcb_info_file) and os.path.exists(tcb_certs_file):
        try:
            # Load TCB Info from existing file
            with open(tcb_info_file, "r") as f:
                tcb_info_raw = f.read()

            # Load certificate chain from existing file
            with open(tcb_certs_file, "r") as f:
                tcb_certs_string_decoded = f.read()

            certs = x509.load_pem_x509_certificates(tcb_certs_string_decoded.encode())
            logger.info(f"Loaded existing TCB Info from {tcb_info_file}")

            return tcb_info_raw, certs
        except Exception as e:
            logger.warning(
                f"Failed to load existing TCB Info files: {e}. Fetching from Intel PCS..."
            )

    # Files don't exist or couldn't be loaded, fetch from Intel PCS
    try:
        tcb_info_raw, tcb_certs_string = request_tcb_info(fmspc, update)

        with open(tcb_info_file, "w") as f:
            f.write(tcb_info_raw)

        tcb_certs_string_decoded = unquote(tcb_certs_string)
        with open(tcb_certs_file, "w") as f:
            f.write(tcb_certs_string_decoded)

        certs = x509.load_pem_x509_certificates(tcb_certs_string_decoded.encode())
        logger.info("Successfully fetched TCB Info from Intel PCS")

        return tcb_info_raw, certs
    except Exception as e:
        logger.error(f"Error fetching TCB Info: {e}")
        raise


def fetch_qe_identity(
    certs_dir: str, update: str = "standard"
) -> Tuple[str, List[x509.Certificate]]:
    """
    Fetch and save QE Identity, or load from existing files if they exist.

    Retrieves Quoting Enclave identity information and certificate chain,
    caching results locally for subsequent use.

    Args:
        certs_dir: Directory to save QE identity files
        update: Update policy ("standard" or "early")

    Returns:
        Tuple of (QE Identity JSON string, QE Identity certificate chain)

    Raises:
        Exception: If unable to fetch or load QE identity
    """
    qe_identity_file = os.path.join(certs_dir, f"{update}_qe_identity.json")
    qe_certs_file = os.path.join(certs_dir, f"{update}_qe_identity_issuer_chain.pem")

    # Check if files already exist
    if os.path.exists(qe_identity_file) and os.path.exists(qe_certs_file):
        try:
            # Load QE Identity from existing file
            with open(qe_identity_file, "r") as f:
                qe_identity_raw = f.read()

            # Load certificate chain from existing file
            with open(qe_certs_file, "r") as f:
                qe_certs_string_decoded = f.read()

            certs = x509.load_pem_x509_certificates(qe_certs_string_decoded.encode())
            logger.info(f"Loaded existing QE Identity from {qe_identity_file}")

            return qe_identity_raw, certs
        except Exception as e:
            logger.warning(
                f"Failed to load existing QE Identity files: {e}. Fetching from Intel PCS..."
            )

    # Files don't exist or couldn't be loaded, fetch from Intel PCS
    try:
        qe_identity_raw, qe_certs_string = request_qe_identity(update)

        with open(qe_identity_file, "w") as f:
            f.write(qe_identity_raw)

        qe_certs_string_decoded = unquote(qe_certs_string)
        with open(qe_certs_file, "w") as f:
            f.write(qe_certs_string_decoded)

        certs = x509.load_pem_x509_certificates(qe_certs_string_decoded.encode())
        logger.info("Successfully fetched QE Identity from Intel PCS")

        return qe_identity_raw, certs
    except Exception as e:
        logger.error(f"Error fetching QE Identity: {e}")
        raise


def fetch_crls(
    encoding: CertFormat, certs_dir: str, ca: str = "platform"
) -> Tuple[
    x509.Certificate, x509.CertificateRevocationList, x509.CertificateRevocationList
]:
    """
    Fetch and save Certificate Revocation Lists (PCK Platform and Processor CRLs).

    Retrieves Root CA certificate and associated CRLs for PCK certificate
    validation, saving them in the specified format.

    Args:
        encoding: Certificate format (PEM or DER)
        certs_dir: Directory to save CRL files
        ca: CA type for PCK CRL ("platform" or "processor")

    Returns:
        Tuple of (root certificate, root CRL, PCK CRL)

    Raises:
        Exception: If unable to fetch certificates or CRLs
    """
    try:
        # Fetch PCK CRL for the specified CA type
        logger.info(f"Fetching PCK CRL for CA type: {ca}...")
        pck_crl = request_pck_crl(ca)
        write_crl(certs_dir, "intel_sgx_pck_" + ca + "_crl", pck_crl, encoding)
        logger.info(f"Successfully fetched PCK {ca} CRL")
    except Exception as e:
        logger.error(f"Error fetching PCK CRL: {e}")
        raise
    try:
        # Fetch Root CA CRL
        root_cert, root_crl = fetch_root_ca_crl(encoding, certs_dir)
    except Exception as e:
        logger.error(f"Error fetching Root CA CRL: {e}")
        raise
    return root_cert, root_crl, pck_crl


def fetch_root_ca_crl(
    encoding: CertFormat, certs_dir: str
) -> Tuple[x509.Certificate, x509.CertificateRevocationList]:
    """
    Fetch Intel SGX Root CA certificate and its CRL.

    Retrieves the Root CA certificate and its associated Certificate
    Revocation List for certificate chain validation.

    Args:
        encoding: Certificate format (PEM or DER)
        certs_dir: Directory to save certificate and CRL files

    Returns:
        Tuple of (root CA certificate, root CA CRL)

    Raises:
        Exception: If unable to fetch root certificate or CRL
    """
    try:
        # Fetch the Root CA certificate
        logger.info("Fetching Intel SGX Root CA certificate...")
        root_cert = request_root_ca_certificate()

        # Save the root certificate
        write_certificate(certs_dir, "intel_sgx_root_ca", root_cert, encoding)
        logger.info("Successfully fetched and saved Root CA certificate")

        # Extract CDP URI and fetch Root CA CRL
        logger.info("Fetching Root CA CRL from certificate CDP URI...")
        root_crl = request_root_ca_crl(root_cert)

        # Save the root CRL
        write_crl(certs_dir, "intel_sgx_root_ca_crl", root_crl, encoding)
        logger.info("Successfully fetched and saved Root CA CRL")

    except Exception as e:
        logger.error(f"Error fetching Root CA certificate or CRL: {e}")
        raise
    return root_cert, root_crl
