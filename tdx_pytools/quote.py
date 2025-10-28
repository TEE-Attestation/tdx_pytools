# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# TDX quote structures - Data classes for parsing and representing Intel TDX quotes.

import struct
from dataclasses import dataclass, fields
from typing import ClassVar, Optional

from . import tdx_logging
from .ecdsa import AttestationKeyType, EcdsaPublicKey, EcdsaSignature
from .qe_report import EnclaveReportBody, QeReportCertificationData

# Get logger for this module
logger = tdx_logging.get_logger(__name__)


@dataclass
class TdQuoteHeader:
    """
    TdQuoteHeader
    Description: Represents the TDX Quote header (48 bytes)
    Based on Intel TDX specification
    """

    version: int  # Quote version (2 bytes)
    att_key_type: AttestationKeyType  # Attestation key type (2 bytes)
    tee_type: int  # TEE type (4 bytes) - should be 0x00000081 for TDX
    reserved_0: bytes  # Reserved field (2 bytes)
    reserved_1: bytes  # Reserved field (2 bytes)
    qe_vendor_id: bytes  # QE Vendor ID (16 bytes)
    user_data: bytes  # User data (20 bytes)

    format_string: ClassVar[str] = (
        "<"
        "H"  # version: u16
        "H"  # att_key_type: u16
        "I"  # tee_type: u32
        "2s"  # reserved_0: [u8; 2]
        "2s"  # reserved_1: [u8; 2]
        "16s"  # qe_vendor_id: [u8; 16]
        "20s"  # user_data: [u8; 20]
    )

    def to_bytes(self) -> bytes:
        """
        Convert the TdQuoteHeader to its binary representation.

        Returns:
            bytes: Binary representation of the TdQuoteHeader (48 bytes)
        """
        return struct.pack(
            self.format_string,
            self.version,
            self.att_key_type.value,
            self.tee_type,
            self.reserved_0,
            self.reserved_1,
            self.qe_vendor_id,
            self.user_data,
        )

    @classmethod
    def unpack(cls, binary_data: bytes, debug: bool = False) -> "TdQuoteHeader":
        """
        Create a TdQuoteHeader instance from binary data.

        Args:
            binary_data: Binary data containing the header (must be 48 bytes)
            debug: If True, print debug information during unpacking

        Returns:
            TdQuoteHeader: Parsed header instance

        Raises:
            struct.error: If binary_data is not the correct size or format
            ValueError: If attestation key type is invalid
        """
        # Unpack the binary data using the format string
        unpacked = struct.unpack(cls.format_string, binary_data)

        # Print unpacked values for debugging
        if debug:
            field_names = [f.name for f in fields(cls)]
            for i, (value, field_name) in enumerate(zip(unpacked, field_names)):
                logger.debug(f"Index {i}: {value} - {field_name}")
                if isinstance(value, bytes):
                    logger.debug(f"  Hex: {value.hex()}")

        # Create and return a TdQuoteHeader instance
        return cls(
            version=unpacked[0],
            att_key_type=AttestationKeyType(unpacked[1]),
            tee_type=unpacked[2],
            reserved_0=unpacked[3],
            reserved_1=unpacked[4],
            qe_vendor_id=unpacked[5],
            user_data=unpacked[6],
        )

    def print_details(self) -> None:
        """
        Print a detailed representation of the TdQuoteHeader.

        Logs header information including version, attestation key type,
        TEE type, and other fields to the console.
        """
        logger.info("=== Quote Header ===")
        logger.info(f"Version:                     {self.version}")
        logger.info(
            f"Attestation Key Type:        {self.att_key_type.value} ({self.att_key_type.name})"
        )
        logger.info(f"TEE Type:                    0x{self.tee_type:08x}")
        logger.info(f"Reserved 0:                  0x{self.reserved_0.hex()}")
        logger.info(f"Reserved 1:                  0x{self.reserved_1.hex()}")
        logger.info(f"QE Vendor ID:                {self.qe_vendor_id.hex()}")
        logger.info(f"User Data:                   {self.user_data.hex()}")


@dataclass
class TdQuoteBody:
    """
    Represents the TDX TD Report body (584 bytes total).

    Contains measurements and attributes of a Trust Domain (TD) including
    runtime measurements, TD attributes, SEAM module measurements, and
    additional report data.

    Based on Intel TDX specification section A.3.2
    Ref: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf
    """

    tee_tcb_svn: bytes  # TEE_TCB_SVN Array (16 bytes)
    mr_seam: bytes  # Measurement of the SEAM module (48 bytes)
    mr_signer_seam: bytes  # Measurement of 3rd party SEAM module's signer (48 bytes)
    seam_attributes: bytes  # SEAM attributes (8 bytes)
    td_attributes: bytes  # TD attributes (8 bytes)
    xfam: bytes  # TD XFAM (8 bytes)
    mr_td: bytes  # Measurement of initial TD contents (48 bytes)
    mr_config_id: bytes  # Software defined config ID (48 bytes)
    mr_owner: bytes  # Software defined TD owner ID (48 bytes)
    mr_owner_config: bytes  # Software defined owner config ID (48 bytes)
    rtmr0: bytes  # Runtime measurement register 0 (48 bytes)
    rtmr1: bytes  # Runtime measurement register 1 (48 bytes)
    rtmr2: bytes  # Runtime measurement register 2 (48 bytes)
    rtmr3: bytes  # Runtime measurement register 3 (48 bytes)
    report_data: bytes  # Additional report data (64 bytes)

    format_string: ClassVar[str] = (
        "<"
        "16s"  # tee_tcb_svn: [u8; 16]
        "48s"  # mr_seam: [u8; 48]
        "48s"  # mr_signer_seam: [u8; 48]
        "8s"  # seam_attributes: [u8; 8]
        "8s"  # td_attributes: [u8; 8]
        "8s"  # xfam: [u8; 8]
        "48s"  # mr_td: [u8; 48]
        "48s"  # mr_config_id: [u8; 48]
        "48s"  # mr_owner: [u8; 48]
        "48s"  # mr_owner_config: [u8; 48]
        "48s"  # rtmr0: [u8; 48]
        "48s"  # rtmr1: [u8; 48]
        "48s"  # rtmr2: [u8; 48]
        "48s"  # rtmr3: [u8; 48]
        "64s"  # report_data: [u8; 64]
    )

    def to_bytes(self) -> bytes:
        """
        Convert the TdQuoteBody to its binary representation.

        Returns:
            bytes: Binary representation of the TdQuoteBody (584 bytes)
        """
        return struct.pack(
            self.format_string,
            self.tee_tcb_svn,
            self.mr_seam,
            self.mr_signer_seam,
            self.seam_attributes,
            self.td_attributes,
            self.xfam,
            self.mr_td,
            self.mr_config_id,
            self.mr_owner,
            self.mr_owner_config,
            self.rtmr0,
            self.rtmr1,
            self.rtmr2,
            self.rtmr3,
            self.report_data,
        )

    @classmethod
    def unpack_v4(cls, binary_data: bytes, debug: bool = False) -> "TdQuoteBody":
        """
        Create a TdQuoteBody instance from binary data of a version 4 quote.

        Args:
            binary_data: Binary data containing the TD report body (must be 584 bytes)
            debug: If True, print debug information during unpacking

        Returns:
            TdQuoteBody: Parsed TD report body instance

        Raises:
            struct.error: If binary_data is not the correct size or format
        """
        # Unpack the binary data using the format string
        unpacked = struct.unpack(cls.format_string, binary_data)

        # Print unpacked values for debugging
        if debug:
            field_names = [f.name for f in fields(cls)]
            for i, (value, field_name) in enumerate(zip(unpacked, field_names)):
                logger.debug(f"Index {i}: {value} - {field_name}")
                if isinstance(value, bytes):
                    logger.debug(f"  Hex: {value.hex()}")

        # Create and return a TdQuoteBody instance
        return cls(
            tee_tcb_svn=unpacked[0],
            mr_seam=unpacked[1],
            mr_signer_seam=unpacked[2],
            seam_attributes=unpacked[3],
            td_attributes=unpacked[4],
            xfam=unpacked[5],
            mr_td=unpacked[6],
            mr_config_id=unpacked[7],
            mr_owner=unpacked[8],
            mr_owner_config=unpacked[9],
            rtmr0=unpacked[10],
            rtmr1=unpacked[11],
            rtmr2=unpacked[12],
            rtmr3=unpacked[13],
            report_data=unpacked[14],
        )

    def print_details(self) -> None:
        """
        Print a detailed representation of the TdQuoteBody.

        Logs all TD measurements, attributes, runtime measurements,
        and report data to the console in hexadecimal format.
        """
        logger.info("\n=== TD Quote Body ===")
        logger.info(f"TEE TCB SVN:                 {self.tee_tcb_svn.hex()}")

        logger.info("\n=== SEAM Measurements ===")
        logger.info(f"MR SEAM:                     {self.mr_seam.hex()}")
        logger.info(f"MR Signer SEAM:              {self.mr_signer_seam.hex()}")

        logger.info("\n=== Attributes ===")
        logger.info(f"SEAM Attributes:             {self.seam_attributes.hex()}")
        logger.info(f"TD Attributes:               {self.td_attributes.hex()}")
        logger.info(f"XFAM:                        {self.xfam.hex()}")

        logger.info("\n=== TD Measurements ===")
        logger.info(f"MR TD (MRTD):                {self.mr_td.hex()}")
        logger.info(f"MR Config ID:                {self.mr_config_id.hex()}")
        logger.info(f"MR Owner:                    {self.mr_owner.hex()}")
        logger.info(f"MR Owner Config:             {self.mr_owner_config.hex()}")

        logger.info("\n=== Runtime Measurements ===")
        logger.info(f"RTMR0:                       {self.rtmr0.hex()}")
        logger.info(f"RTMR1:                       {self.rtmr1.hex()}")
        logger.info(f"RTMR2:                       {self.rtmr2.hex()}")
        logger.info(f"RTMR3:                       {self.rtmr3.hex()}")

        logger.info("\n=== Report Data ===")
        logger.info(f"Report Data:                 {self.report_data.hex()}")


@dataclass
class QuoteSignatureData:
    """
    Represents the complete quote signature data structure.

    Contains the attestation key, signature, and QE certification data
    required for TDX quote verification.

    Based on Intel TDX specification
    """

    signature: EcdsaSignature  # Quote signature (ECDSA signature)
    attestation_key: EcdsaPublicKey  # Attestation key (ECDSA public key)
    qe_cert_data_type: int  # QE Certification Data Type (2 bytes)
    qe_cert_data_size: int  # QE Certification Data Size (4 bytes)
    qe_cert_data: QeReportCertificationData  # QE certification data

    @classmethod
    def unpack(
        cls,
        binary_data: bytes,
        att_key_type: AttestationKeyType,
        debug: bool = False,
    ) -> "QuoteSignatureData":
        """
        Create a QuoteSignatureData instance from binary data.

        Args:
            binary_data: Binary data containing the quote signature data
            att_key_type: The attestation key type from the quote header
            debug: If True, print debug information during unpacking

        Returns:
            QuoteSignatureData: Parsed signature data instance

        Raises:
            ValueError: If binary_data is too small or invalid
        """
        if (
            len(binary_data) < 128 + 6
        ):  # Need at least signature + key + type + size fields
            raise ValueError(
                f"Insufficient signature data: expected at least {128 + 6} bytes, got {len(binary_data)}"
            )

        # Extract fixed-size fields
        signature_bytes = binary_data[:64]
        # Parse ECDSA signature using the key type from header
        signature = EcdsaSignature.from_bytes(signature_bytes, att_key_type)
        attestation_key_bytes = binary_data[64:128]
        attestation_key = EcdsaPublicKey.from_uncompressed_bytes(
            attestation_key_bytes, att_key_type
        )
        qe_cert_data_type = struct.unpack("<H", binary_data[128:130])[0]
        qe_cert_data_size = struct.unpack("<I", binary_data[130:134])[0]

        if debug:
            logger.debug(
                f"QE Certification Data Type: {qe_cert_data_type}"
            )  # Should be type 6
            logger.debug(f"QE Certification Data Length: {qe_cert_data_size} bytes")

        # Validate QE certification data size
        if len(binary_data) < 134 + qe_cert_data_size:
            raise ValueError(
                f"Insufficient QE certification data: expected at least {134 + qe_cert_data_size} bytes, got {len(binary_data)}"
            )

        # Extract and parse QE report certification data
        qe_cert_data_bytes = binary_data[134 : 134 + qe_cert_data_size]
        qe_cert_data = QeReportCertificationData.unpack(
            qe_cert_data_bytes, att_key_type, debug=debug
        )

        return cls(
            signature=signature,
            attestation_key=attestation_key,
            qe_cert_data_type=qe_cert_data_type,
            qe_cert_data_size=qe_cert_data_size,
            qe_cert_data=qe_cert_data,
        )

    def to_bytes(self) -> bytes:
        """
        Convert the QuoteSignatureData to its binary representation.

        Returns:
            bytes: Binary representation of the QuoteSignatureData
        """
        result = self.signature.to_bytes()
        result += self.attestation_key.to_uncompressed_bytes()
        result += struct.pack("<H", self.qe_cert_data_type)
        result += struct.pack("<I", self.qe_cert_data_size)
        result += self.qe_cert_data.to_bytes()
        return result


@dataclass
class Quote:
    """
    Represents a complete TDX/SGX attestation quote.

    A complete quote contains a header with metadata, a body with TD measurements,
    and signature data for cryptographic verification.

    Based on Intel TDX specification
    """

    header: TdQuoteHeader
    body: TdQuoteBody
    signature_len: int
    signature_data: QuoteSignatureData
    remainder: bytes = (
        b""  # Optional field for any remaining data or padding after the quote
    )

    def to_bytes(self) -> bytes:
        """
        Convert the Quote to its binary representation.

        Returns:
            bytes: Complete binary representation of the quote
        """
        result = self.header.to_bytes()
        result += self.body.to_bytes()
        result += struct.pack("<I", self.signature_len)
        result += self.signature_data.to_bytes()

        # Append any remaining data if present
        if self.remainder:
            result += self.remainder

        return result

    @classmethod
    def unpack(cls, binary_data: bytes, debug: bool = False) -> "Quote":
        """
        Create a Quote instance from binary data.

        Args:
            binary_data: Binary data containing the complete quote
            debug: If True, print debug information during unpacking

        Returns:
            Quote: Parsed quote instance

        Raises:
            ValueError: If quote version is unsupported or data is insufficient
            struct.error: If binary data format is invalid
        """
        if debug:
            logger.debug(f"Parsing quote, total size: {len(binary_data)} bytes")

        # Parse header (48 bytes)
        header_data = binary_data[:48]
        header = TdQuoteHeader.unpack(header_data, debug=debug)

        if debug:
            logger.debug(f"Header parsed, TEE type: 0x{header.tee_type:08x}")

        # Check version of quote
        if header.version in [3, 4]:
            # Parse TD Report (584 bytes, starts after header)
            body_data = binary_data[48 : 48 + 584]
            body = TdQuoteBody.unpack_v4(body_data, debug=debug)

            # Set offset for start of signature length (4 bytes) and signature data
            signature_offset = 48 + 584  # After header and TD report
        elif header.version == 5:
            # TODO: Implement parsing for version 5
            # TODO: signature_offset = 48 + 584? (spec says 584 but it contains variable lengths...)
            raise ValueError(
                f"Unsupported quote version: Version {header.version} is not yet implemented."
            )
        else:
            raise ValueError(f"Unsupported quote version: {header.version}")

        if len(binary_data) < signature_offset + 4:
            raise ValueError(
                f"Insufficient data for signature length: expected at least {signature_offset + 4} bytes, got {len(binary_data)}"
            )

        quote_signature_len = struct.unpack_from("<I", binary_data, signature_offset)[0]

        # Validate signature data is present and complete
        expected_min_size = signature_offset + 4 + quote_signature_len
        if len(binary_data) < expected_min_size:
            raise ValueError(
                f"Insufficient signature data: expected at least {expected_min_size} bytes, got {len(binary_data)} (signature length shows {quote_signature_len} bytes)"
            )

        # Extract and parse the signature data using the structured approach
        quote_signature_data_bytes = binary_data[
            signature_offset + 4 : signature_offset + 4 + quote_signature_len
        ]

        quote_signature_data = QuoteSignatureData.unpack(
            quote_signature_data_bytes, header.att_key_type, debug=debug
        )

        # Check for any remaining data after the quote
        remainder = binary_data[expected_min_size:]
        if debug and len(remainder) > 0:
            logger.debug(
                f"Length of remaining data after signature: {len(remainder)} bytes"
            )
            logger.debug(f"Remainder data: {remainder.hex()}")

        return cls(
            header=header,
            body=body,
            signature_len=quote_signature_len,
            signature_data=quote_signature_data,
            remainder=remainder,
        )

    def print_details(self) -> None:
        """
        Print a detailed representation of the Quote.

        Outputs a comprehensive view of the quote including header information,
        TD measurements, runtime measurements, and signature details.
        """
        # We dont include reserved fields, they can be printed by using the print methods in TdQuoteHeader and TdQuoteBody
        logger.info("TDX Quote Details:")
        logger.info(f"\nHeader:")
        logger.info(f"Version:                     {self.header.version}")
        logger.info(
            f"Attestation Key Type:        {self.header.att_key_type.value} ({self.header.att_key_type.name})"
        )
        logger.info(f"TEE Type:                    0x{self.header.tee_type:08x}")
        logger.info(f"QE Vendor ID:                {self.header.qe_vendor_id.hex()}")
        logger.info(f"User Data:                   {self.header.user_data.hex()}")

        logger.info("\nBody:")
        logger.info(f"TEE TCB SVN:                 {self.body.tee_tcb_svn.hex()}")

        logger.info("\nSEAM Measurements:")
        logger.info(f"  MR SEAM:                   {self.body.mr_seam.hex()}")
        logger.info(f"  MR Signer SEAM:            {self.body.mr_signer_seam.hex()}")

        logger.info("\nAttributes:")
        logger.info(f"  SEAM Attributes:           {self.body.seam_attributes.hex()}")
        logger.info(f"  TD Attributes:             {self.body.td_attributes.hex()}")
        logger.info(f"  XFAM:                      {self.body.xfam.hex()}")

        logger.info("\nTD Measurements:")
        logger.info(f"  MR TD (MRTD):              {self.body.mr_td.hex()}")
        logger.info(f"  MR Config ID:              {self.body.mr_config_id.hex()}")
        logger.info(f"  MR Owner:                  {self.body.mr_owner.hex()}")
        logger.info(f"  MR Owner Config:           {self.body.mr_owner_config.hex()}")

        logger.info("\nRuntime Measurements:")
        logger.info(f"  RTMR0:                     {self.body.rtmr0.hex()}")
        logger.info(f"  RTMR1:                     {self.body.rtmr1.hex()}")
        logger.info(f"  RTMR2:                     {self.body.rtmr2.hex()}")
        logger.info(f"  RTMR3:                     {self.body.rtmr3.hex()}")

        logger.info(f"\nReport Data:                 {self.body.report_data.hex()}")

        logger.info(f"\nQuote Signature Length:      {self.signature_len} bytes")
        logger.info(f"\nQuote Signature Data:")
        logger.info(
            f"  Quote Signature (r):       {self.signature_data.signature.r.hex()}"
        )
        logger.info(
            f"  Quote Signature (s):       {self.signature_data.signature.s.hex()}"
        )
        logger.info(
            f"  Attestation Key Type:      {self.signature_data.attestation_key.curve_type.name}"
        )
        logger.info(
            f"  Attestation Key (x):       {self.signature_data.attestation_key.x.hex()}"
        )
        logger.info(
            f"  Attestation Key (y):       {self.signature_data.attestation_key.y.hex()}"
        )
        logger.info(
            f"  QE Cert Data Type:         {self.signature_data.qe_cert_data_type}"
        )
        logger.info(
            f"  QE Cert Data Size:         {self.signature_data.qe_cert_data_size} bytes"
        )

        qe_data = self.signature_data.qe_cert_data
        logger.info(f"  QE Report Certification:")
        logger.info(
            f"    QE Report Signature (r): {qe_data.qe_report_signature.r.hex()}"
        )
        logger.info(
            f"    QE Report Signature (s): {qe_data.qe_report_signature.s.hex()}"
        )
        logger.info(
            f"    Auth Data Size:          {qe_data.qe_authentication_data_size} bytes"
        )
        logger.info(
            f"    Cert Data Type:          {qe_data.qe_certification_data_type}"
        )
        logger.info(
            f"    Cert Data Size:          {qe_data.qe_certification_data_size} bytes"
        )
        logger.info("\n QE Report Body:")
        self.signature_data.qe_cert_data.qe_report.print_details()
