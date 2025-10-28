# tdx_pytools

A Python library and CLI tool for Intel TDX (Trust Domain Extensions) attestation quote verification. This project provides functionality for parsing, validating, and verifying TDX attestation quotes, including cryptographic signature verification, certificate chain validation, and TCB (Trusted Computing Base) status evaluation.

## Overview

Intel TDX (Trust Domain Extensions) is a confidential computing technology that provides hardware-assisted isolation for virtual machines. TDX attestation quotes are cryptographic evidence that prove the integrity and authenticity of a TDX-enabled system.

### Key Features

- **Complete Quote Parsing**: Parse TDX attestation quotes
- **Cryptographic Verification**: ECDSA signature verification for both P-256 and P-384 curves
- **Certificate Chain Validation**: Full X.509 certificate chain verification with CRL checking
- **TCB Status Evaluation**: Trusted Computing Base level matching and status assessment
- **Intel PCS Integration**: Automatic fetching of certificates and collateral from Intel's Provisioning Certification Service
- **QE Identity Verification**: Quoting Enclave identity validation
- **Comprehensive Logging**: Detailed verification steps with configurable logging levels
- **CLI Tools**: Ready-to-use command-line utilities for quote inspection and verification

## Architecture

The library is organized as follows:

### Core Components

- **`quote.py`**: TDX quote structure parsing and representation
  - `TdQuoteHeader`: Quote header parsing (48 bytes)
  - `TdQuoteBody`: TD Report body parsing (584 bytes for v4)
  - `Quote`: Complete quote structure with signature data

- **`verify.py`**: Complete attestation verification pipeline
  - Quote signature verification using attestation key
  - QE report signature verification using PCK certificate
  - Attestation key binding validation
  - Certificate chain verification
  - TCB status evaluation

### Supporting Modules

- **`ecdsa.py`**: ECDSA cryptographic structures and utilities
- **`qe_report.py`**: Quoting Enclave report parsing
- **`tdx_logging.py`**: Centralized logging configuration
- **`certs.py`**: X.509 certificate handling and SGX extension parsing
- **`tcb.py`**: TCB Info processing and status evaluation
- **`fetch.py`**: Intel PCS API integration
- **`tdx_logging.py`**: Logging capabilities for command line and library
- **`print_quote.py`**: Quote display



## Installation

### Requirements

- Python 3.7+
- Dependencies (automatically installed):
  - `cryptography >= 39.0.0`
  - `requests >= 2.25.0`
  - `pyasn1 >= 0.4.8`
  - `urllib3 >= 1.26.0`

### Install from Source

```bash
git clone https://github.com/Isaac-Matthews/tdx_pytools.git
cd tdx_pytools
pip install .
```

### Development Installation

```bash
pip install -e .
```

### Uninstallation

```bash
pip uninstall tdx_pytools
```

## Usage

### Command Line Tools

#### Print Quote Details

Display the contents of a TDX attestation quote in human-readable format:

```bash
# Using the installed command
tdx-print -f quote.dat

# With debug output
tdx-print -f quote.dat -d

# Using Python module directly
python -m tdx_pytools.print_quote -f quote.dat
```

**Options:**
- `-f, --file`: Path to the TDX quote file (default: `quote.dat`)
- `-d, --debug`: Enable debug mode for detailed parsing information

#### Verify Quote Authenticity

Perform complete cryptographic verification of a TDX attestation quote:

```bash
# Basic verification
tdx-verify -f quote.dat

# Verbose verification with detailed steps
tdx-verify -f quote.dat -v

# Debug mode with maximum detail
tdx-verify -f quote.dat -d

# Show report data after successful verification
tdx-verify -f quote.dat -r

# Use local certificates instead of fetching from Intel
tdx-verify -f quote.dat -c ./certs/

# Use early update policy for fetching collateral
tdx-verify -f quote.dat -e
```

**Options:**
- `-f, --file`: Path to the TDX quote file (default: `quote.dat`)
- `-d, --debug`: Enable debug mode for quote parsing (implies verbose)
- `-v, --verbose`: Enable verbose verification output
- `-r, --reportdata`: Display report data after successful verification
- `-c, --certs`: Path to local certificate directory (default: `./certs`)
- `-e, --early`: Use early update policy for fetching collateral

### Python API

#### Basic Quote Parsing

```python
from tdx_pytools import Quote

# Load and parse a quote
with open('quote.dat', 'rb') as f:
    quote_data = f.read()

quote = Quote.unpack(quote_data)

# Access quote components
print(f"Quote version: {quote.header.version}")
print(f"TEE type: 0x{quote.header.tee_type:08x}")
print(f"Attestation key type: {quote.header.att_key_type}")

# Display quote details
quote.print_details()
```

#### Complete Quote Verification

```python
from tdx_pytools import verify_quote, verify_quote_bytes, Quote

# Parse quote
with open('quote.dat', 'rb') as f:
    quote_bytes = f.read()

# Verify quote
quote = Quote.unpack(quote_bytes)
report_data, collateral, tcb_dict, combined_status = verify_quote(quote)

```

## Verification Process

The library implements a comprehensive 12-step verification process as documented in `VERIFICATION_PROCESS.md`:

1. **Quote Structure Verification**: Validate quote format and basic properties
2. **Certificate Loading**: Load or fetch required Intel certificates and CRLs
3. **Certificate Chain Verification**: Verify PCK certificate chain to Intel Root CA
4. **Certificate Revocation Checks**: Ensure no certificates are revoked
5. **Cryptographic Signature Verification**: Verify quote and QE report signatures
6. **Attestation Key Binding**: Validate attestation key binding to QE report
7. **SGX Extension Extraction**: Parse Intel SGX-specific certificate extensions
8. **QE Identity Verification**: Verify Quoting Enclave identity and status
9. **TCB Info Verification**: Validate TCB Info document and signatures
10. **TCB Status Evaluation**: Determine platform TCB status
11. **TD Debug Mode Check**: Verify Trust Domain is not in debug mode
12. **Terminal TCB Status Check**: Ensure platform is not in terminal state

For detailed information about each step, see [VERIFICATION_PROCESS.md](VERIFICATION_PROCESS.md).

## Certificate Management

### Automatic Certificate Fetching

By default, the library automatically fetches certificates and collateral from Intel's Provisioning Certification Service (PCS):

- Intel SGX Root CA Certificate
- Intel SGX Root CA CRL
- Intel SGX PCK Platform CRL
- QE Identity document
- TCB Info document

### Local Certificate Storage

For offline verification or to avoid network requests, certificates and collateral are stored locally:

```
certs/
├── intel_sgx_root_ca.pem
├── intel_sgx_root_ca_crl.pem
├── intel_sgx_pck_platform_crl.pem
├── {update}_qe_identity.json
├── {update}_qe_identity_issuer_chain.pem
├── {fmspc}_{update}_tcb_info.json
└── {fmspc}_{update}_tcb_info_issuer_chain.pem
```

## Logging and Debugging

The library provides comprehensive logging with multiple levels:

```python
import tdx_pytools.tdx_logging as logging

# Setup CLI-style logging with colors
logger = logging.setup_cli_logging(verbose=True, quiet=False)

# Setup library-style logging
logger = logging.setup_logging(
    level='DEBUG',
    cli_mode=False,
    log_file='verification.log'
)
```

## Platform Support

### Supported Quote Versions
- Version 3 TDX quotes
- Version 4 TDX quotes

### Not currently supported
- Version 5 TDX quotes

### Supported Attestation Key Types
- Type 2: ECDSA-256 with P-256 curve
- Type 3: ECDSA-384 with P-384 curve

## Contributing

Contributions are welcome! Please follow the contribution guidelines in the [TAS repository](https://github.com/TEE-Attestation/tas/blob/main/CONTRIBUTING.md).


## License

MIT License - Copyright 2025 Hewlett Packard Enterprise Development LP.

See [LICENSE](LICENSE) file for details.
