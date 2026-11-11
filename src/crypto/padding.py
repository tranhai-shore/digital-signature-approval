"""EMSA-PKCS1-v1_5 encoding for RSA signatures.

The encoding is defined in RFC 8017, section 9.2:

    EM = 0x00 || 0x01 || PS || 0x00 || T
    T  = DigestInfo(SHA-256) || SHA-256(message)
    PS = 0xFF repeated until the encoded message has the modulus length

Strict decoding is essential: verifying only the trailing digest would accept
malformed or attacker-chosen encodings.  This module checks the whole
structure, including the DigestInfo prefix and the minimum PS length.
"""

from __future__ import annotations

import hmac

SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
SHA256_DIGEST_SIZE = 32
MIN_PS_LENGTH = 8
# EM must contain at least the header (3 bytes), PS (8) and T (19 + 32).
MIN_EM_LENGTH = 3 + MIN_PS_LENGTH + len(SHA256_DIGEST_INFO) + SHA256_DIGEST_SIZE


class PaddingError(ValueError):
    """Raised when an encoded message is not valid EMSA-PKCS1-v1_5."""


def encode_pkcs1_v1_5(digest: bytes, em_len: int) -> bytes:
    """Return the EMSA-PKCS1-v1_5 encoded message for a SHA-256 digest.

    ``em_len`` must equal the RSA modulus length in bytes (256 for RSA-2048).
    """

    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"digest must be {SHA256_DIGEST_SIZE} bytes")
    if em_len < MIN_EM_LENGTH:
        raise ValueError(
            f"em_len must be at least {MIN_EM_LENGTH} bytes for SHA-256"
        )

    digest_info = SHA256_DIGEST_INFO + digest
    ps_length = em_len - len(digest_info) - 3
    return b"\x00\x01" + (b"\xff" * ps_length) + b"\x00" + digest_info


def decode_pkcs1_v1_5(em: bytes) -> bytes:
    """Validate an EMSA-PKCS1-v1_5 block and return its SHA-256 digest.

    Raises ``PaddingError`` for any structural deviation.  The comparison of
    the DigestInfo prefix uses ``hmac.compare_digest`` for consistency with the
    digest comparison performed by the caller.
    """

    if len(em) < MIN_EM_LENGTH:
        raise PaddingError("encoded message is too short")
    if em[0] != 0x00 or em[1] != 0x01:
        raise PaddingError("invalid PKCS#1 v1.5 block type")

    separator = em.find(b"\x00", 2)
    if separator < 0:
        raise PaddingError("missing 0x00 separator")

    padding = em[2:separator]
    if len(padding) < MIN_PS_LENGTH:
        raise PaddingError("padding string is shorter than 8 bytes")
    if padding != b"\xff" * len(padding):
        raise PaddingError("padding string must contain only 0xFF bytes")

    encoded_digest_info = em[separator + 1 :]
    if len(encoded_digest_info) != len(SHA256_DIGEST_INFO) + SHA256_DIGEST_SIZE:
        raise PaddingError("invalid DigestInfo length")

    prefix = encoded_digest_info[: len(SHA256_DIGEST_INFO)]
    if not hmac.compare_digest(prefix, SHA256_DIGEST_INFO):
        raise PaddingError("DigestInfo does not identify SHA-256")

    return encoded_digest_info[len(SHA256_DIGEST_INFO) :]
