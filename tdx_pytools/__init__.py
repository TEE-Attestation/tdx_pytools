# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# tdx_pytools - Python tools for Intel TDX attestation.

"""
tdx_pytools - Python tools for Intel TDX attestation

This package provides tools for working with Intel TDX attestation quotes,
including parsing, verification, certificate management, and TCB validation.
"""

# Certificate and verification functions
from .certs import (
    PCKCertChain,
    check_certificate_against_crl,
    export_certificates,
    get_certificate_extension,
    parse_sgx_extensions,
    print_certificate_details,
    validate_certificate_dates,
    verify_certificate,
    verify_crl,
)

# ECDSA cryptographic components
from .ecdsa import (
    AttestationKeyType,
    EcdsaPublicKey,
    EcdsaSignature,
    get_hash_algorithm,
)

# Fetching certificates and collateral
from .fetch import (
    CertFormat,
    fetch_crls,
    fetch_qe_identity,
    fetch_root_ca_crl,
    fetch_tcb_info,
    request_pck_crl,
    request_qe_identity,
    request_root_ca_certificate,
    request_root_ca_crl,
    request_tcb_info,
    validate_fmspc,
    write_certificate,
    write_crl,
    write_json_data,
)

# Policy validation
from .policy import AttestationPolicy, PolicyValidationError, validate_quote_with_policy

# QE Report structures
from .qe_report import EnclaveReportBody, QeReportCertificationData

# Core attestation quote components
from .quote import Quote, QuoteSignatureData, TdQuoteBody, TdQuoteHeader

# TCB handling and status
from .tcb import Tcb, TcbStatus, combine_tcb_status, tcb_verify

# Logging utilities
from .tdx_logging import (
    get_logger,
    log_certificate_info,
    log_function_entry,
    log_function_exit,
    log_network_request,
    log_policy_validation,
    log_section_header,
    log_subsection_header,
    log_verification_step,
    setup_cli_logging,
    setup_library_logging,
    setup_logging,
)

# High-level verification functions
from .verify import (
    load_certificates_and_collateral,
    perform_verification_checks,
    verify_attestation_key_binding,
    verify_qe_report_signature,
    verify_quote,
    verify_quote_bytes,
    verify_quote_signature,
    verify_quote_structure,
    verify_td_attributes,
)

__version__ = "0.1.1"
__author__ = "Isaac Matthews"

__all__ = [
    # Core classes
    "Quote",
    "TdQuoteHeader",
    "TdQuoteBody",
    "QuoteSignatureData",
    "PCKCertChain",
    "EnclaveReportBody",
    "QeReportCertificationData",
    "Tcb",
    "TcbStatus",
    # ECDSA components
    "AttestationKeyType",
    "EcdsaPublicKey",
    "EcdsaSignature",
    "get_hash_algorithm",
    # Certificate functions
    "check_certificate_against_crl",
    "export_certificates",
    "get_certificate_extension",
    "parse_sgx_extensions",
    "print_certificate_details",
    "validate_certificate_dates",
    "verify_certificate",
    "verify_crl",
    # Policy validation
    "AttestationPolicy",
    "PolicyValidationError",
    "validate_quote_with_policy",
    # Fetching and collateral
    "CertFormat",
    "fetch_crls",
    "fetch_qe_identity",
    "fetch_root_ca_crl",
    "fetch_tcb_info",
    "request_pck_crl",
    "request_qe_identity",
    "request_root_ca_certificate",
    "request_root_ca_crl",
    "request_tcb_info",
    "validate_fmspc",
    "write_certificate",
    "write_crl",
    "write_json_data",
    # TCB handling
    "combine_tcb_status",
    "tcb_verify",
    # High-level verification
    "load_certificates_and_collateral",
    "perform_verification_checks",
    "verify_attestation_key_binding",
    "verify_qe_report_signature",
    "verify_quote",
    "verify_quote_bytes",
    "verify_quote_signature",
    "verify_quote_structure",
    "verify_td_attributes",
    # Logging utilities
    "get_logger",
    "setup_cli_logging",
    "setup_library_logging",
    "setup_logging",
    "log_verification_step",
    "log_certificate_info",
    "log_policy_validation",
    "log_network_request",
    "log_function_entry",
    "log_function_exit",
    "log_section_header",
    "log_subsection_header",
]
