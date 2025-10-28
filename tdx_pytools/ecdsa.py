# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# ECDSA structures - ECDSA signature and public key data structures.

import enum
import logging
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

logger = logging.getLogger(__name__)


class AttestationKeyType(enum.Enum):
    """
    Attestation Key Types for TDX quotes
    """

    ECDSA_P256 = 2
    ECDSA_P384 = 3


def get_hash_algorithm(att_key_type: AttestationKeyType) -> hashes.HashAlgorithm:
    """
    Get the appropriate hash algorithm based on attestation key type.

    Maps ECDSA curve types to their corresponding hash algorithms as per
    Intel TDX specification requirements.

    Args:
        att_key_type: AttestationKeyType enum value

    Returns:
        hashes.HashAlgorithm: The appropriate hash algorithm (SHA256 or SHA384)

    Raises:
        ValueError: If attestation key type is not supported
    """
    if att_key_type.value == 2:  # P-256
        logger.debug("Using Attestation Key Type 2: ECDSA-256-with-P-256 curve")
        return hashes.SHA256()
    elif att_key_type.value == 3:  # P-384
        logger.debug("Using Attestation Key Type 3: ECDSA-384-with-P-384 curve")
        return hashes.SHA384()
    else:
        raise ValueError(f"Unsupported attestation key type: {att_key_type}")


@dataclass
class EcdsaPublicKey:
    """
    ECDSA public key components for P-256 or P-384 curves.

    Represents an elliptic curve public key as separate x and y coordinates
    along with the curve type for cryptographic operations.
    """

    x: bytes
    y: bytes
    curve_type: AttestationKeyType

    def __init__(self, x: bytes, y: bytes, curve_type: AttestationKeyType) -> None:
        """
        Initialize ECDSA public key.

        Args:
            x: x coordinate of the public key point
            y: y coordinate of the public key point
            curve_type: The curve type (P-256 or P-384)
        """
        self.x = x
        self.y = y
        self.curve_type = curve_type

    @classmethod
    def from_uncompressed_bytes(
        cls, key_bytes: bytes, curve_type: AttestationKeyType
    ) -> "EcdsaPublicKey":
        """
        Create ECDSA public key from uncompressed byte representation.

        Parses the standard uncompressed point format used in TDX quotes.

        Args:
            key_bytes: Uncompressed public key bytes (64 bytes for P-256, 96 bytes for P-384)
            curve_type: The curve type

        Returns:
            EcdsaPublicKey instance
        """
        if curve_type == AttestationKeyType.ECDSA_P256:
            if len(key_bytes) != 64:
                raise ValueError(
                    f"P-256 public key must be 64 bytes, got {len(key_bytes)}"
                )
            x = key_bytes[:32]
            y = key_bytes[32:64]
        elif curve_type == AttestationKeyType.ECDSA_P384:
            if len(key_bytes) != 96:
                raise ValueError(
                    f"P-384 public key must be 96 bytes, got {len(key_bytes)}"
                )
            x = key_bytes[:48]
            y = key_bytes[48:96]
        else:
            raise ValueError(f"Unsupported curve type: {curve_type}")

        return cls(x, y, curve_type)

    def to_uncompressed_bytes(self) -> bytes:
        """
        Convert to uncompressed byte representation

        Returns:
            Uncompressed public key bytes
        """
        return self.x + self.y

    def to_cryptography_key(self) -> ec.EllipticCurvePublicKey:
        """
        Convert to cryptography library public key object.

        Returns:
            cryptography EllipticCurvePublicKey object for cryptographic operations
        """
        if self.curve_type == AttestationKeyType.ECDSA_P256:
            curve = ec.SECP256R1()
        elif self.curve_type == AttestationKeyType.ECDSA_P384:
            curve = ec.SECP384R1()
        else:
            raise ValueError(f"Unsupported curve type: {self.curve_type}")

        x_int = int.from_bytes(self.x, "big")
        y_int = int.from_bytes(self.y, "big")

        point = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, b"\x04" + self.x + self.y
        )
        return point

    def __repr__(self) -> str:
        """String representation of the ECDSA public key."""
        return f"EcdsaPublicKey(curve={self.curve_type.name}, x={self.x.hex()[:16]}..., y={self.y.hex()[:16]}...)"


@dataclass
class EcdsaSignature:
    """
    ECDSA signature components (r, s values)
    """

    r: bytes
    s: bytes
    curve_type: AttestationKeyType

    def __init__(self, r: bytes, s: bytes, curve_type: AttestationKeyType) -> None:
        """
        Initialize ECDSA signature.

        Args:
            r: r component of the signature
            s: s component of the signature
            curve_type: The curve type (determines component sizes)
        """
        self.r = r
        self.s = s
        self.curve_type = curve_type

    def get_r_int(self) -> int:
        """Get r component as integer"""
        return int.from_bytes(self.r, "big")

    def get_s_int(self) -> int:
        """Get s component as integer."""
        return int.from_bytes(self.s, "big")

    def to_der(self) -> bytes:
        """
        Convert to DER-encoded signature for cryptography library.

        Returns:
            DER-encoded signature bytes
        """
        return utils.encode_dss_signature(self.get_r_int(), self.get_s_int())

    @classmethod
    def from_der(
        cls, der_data: bytes, curve_type: AttestationKeyType
    ) -> "EcdsaSignature":
        """
        Create ECDSA signature from DER-encoded data

        Args:
            der_data: DER-encoded signature
            curve_type: The curve type (determines component sizes)

        Returns:
            EcdsaSignature instance
        """
        r_int, s_int = utils.decode_dss_signature(der_data)

        # Convert to bytes based on curve type
        if curve_type == AttestationKeyType.ECDSA_P256:
            component_size = 32
        elif curve_type == AttestationKeyType.ECDSA_P384:
            component_size = 48
        else:
            raise ValueError(f"Unsupported curve type: {curve_type}")

        r_bytes = r_int.to_bytes(component_size, "big")
        s_bytes = s_int.to_bytes(component_size, "big")

        return cls(r_bytes, s_bytes, curve_type)

    @classmethod
    def from_bytes(
        cls, sig_bytes: bytes, curve_type: AttestationKeyType
    ) -> "EcdsaSignature":
        """
        Create ECDSA signature from raw bytes (r || s)

        Args:
            sig_bytes: Raw signature bytes (r concatenated with s)
            curve_type: The curve type (determines component sizes)

        Returns:
            EcdsaSignature instance
        """
        if curve_type == AttestationKeyType.ECDSA_P256:
            if len(sig_bytes) != 64:
                raise ValueError(
                    f"P-256 signature must be 64 bytes, got {len(sig_bytes)}"
                )
            r = sig_bytes[:32]
            s = sig_bytes[32:64]
        elif curve_type == AttestationKeyType.ECDSA_P384:
            if len(sig_bytes) != 96:
                raise ValueError(
                    f"P-384 signature must be 96 bytes, got {len(sig_bytes)}"
                )
            r = sig_bytes[:48]
            s = sig_bytes[48:96]
        else:
            raise ValueError(f"Unsupported curve type: {curve_type}")

        return cls(r, s, curve_type)

    def to_bytes(self) -> bytes:
        """
        Convert to raw bytes (r || s)

        Returns:
            Raw signature bytes
        """
        return self.r + self.s

    def __repr__(self) -> str:
        """String representation of the ECDSA signature."""
        return f"EcdsaSignature(curve={self.curve_type.name}, r={self.r.hex()[:16]}..., s={self.s.hex()[:16]}...)"
