"""High-level RSA signatures: SHA-256 + EMSA-PKCS1-v1_5.

This is the safe API for signing documents.  It combines three layers:

1. SHA-256 over the document bytes (streaming for files);
2. RFC 8017 EMSA-PKCS1-v1_5 encoding;
3. the raw RSA private/public operation from :mod:`src.crypto.rsa`.

The raw ``sign_int`` / ``verify_int`` methods must not be used directly for
document approval; always go through this module.
"""

from __future__ import annotations

import hmac
import os

from .encoding import bytes_to_int, int_to_bytes
from .hashing import DEFAULT_CHUNK_SIZE, SHA256_DIGEST_SIZE, sha256_bytes, sha256_file
from .padding import PaddingError, decode_pkcs1_v1_5, encode_pkcs1_v1_5
from .rsa import RSAPrivateKey, RSAPublicKey


class SignatureFormatError(ValueError):
    """Raised when a signature has the wrong length or is out of range."""


def _modulus_size_bytes(key: RSAPublicKey | RSAPrivateKey) -> int:
    return (key.n.bit_length() + 7) // 8


def sign_digest(private_key: RSAPrivateKey, digest: bytes) -> bytes:
    """Sign a 32-byte SHA-256 digest and return a fixed-length signature.

    The result is exactly ``ceil(bit_length(n) / 8)`` bytes (256 for RSA-2048),
    including any leading zero bytes.
    """

    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"digest must be {SHA256_DIGEST_SIZE} bytes")

    em_len = _modulus_size_bytes(private_key)
    encoded = encode_pkcs1_v1_5(digest, em_len)
    encoded_int = bytes_to_int(encoded)

    signature_int = private_key.sign_int(encoded_int)

    # Self-check after the CRT computation.  A faulty CRT result must never be
    # released: publishing it can leak the private key (RSA-CRT fault attack).
    if private_key.recover_int(signature_int) != encoded_int:
        raise RuntimeError("RSA signature self-check failed")

    return int_to_bytes(signature_int, em_len)


def recover_digest(public_key: RSAPublicKey, signature: bytes) -> bytes:
    """Recover the SHA-256 digest from a signature.

    Raises ``SignatureFormatError`` for wrong-length/out-of-range signatures and
    ``PaddingError`` for invalid EMSA-PKCS1-v1_5 structure.
    """

    em_len = _modulus_size_bytes(public_key)
    if len(signature) != em_len:
        raise SignatureFormatError(
            f"signature must be exactly {em_len} bytes, got {len(signature)}"
        )

    signature_int = bytes_to_int(signature)
    if signature_int >= public_key.n:
        raise SignatureFormatError("signature representative is >= modulus")

    try:
        encoded_int = public_key.apply(signature_int)
    except ValueError as exc:  # defensive: apply() also validates the range
        raise SignatureFormatError("signature representative is invalid") from exc

    encoded = int_to_bytes(encoded_int, em_len)
    return decode_pkcs1_v1_5(encoded)


def verify_digest(
    public_key: RSAPublicKey,
    digest: bytes,
    signature: bytes,
) -> bool:
    """Return ``True`` only for a well-formed signature over ``digest``.

    Malformed input is reported as ``False`` rather than an exception so the
    caller can present a single "invalid signature" result to the user.
    """

    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"digest must be {SHA256_DIGEST_SIZE} bytes")

    try:
        recovered = recover_digest(public_key, signature)
    except (SignatureFormatError, PaddingError):
        return False
    return hmac.compare_digest(recovered, digest)


def sign_bytes(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """Sign an in-memory document."""

    return sign_digest(private_key, sha256_bytes(data))


def verify_bytes(
    public_key: RSAPublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """Verify an in-memory document against a signature."""

    return verify_digest(public_key, sha256_bytes(data), signature)


def sign_file(
    private_key: RSAPrivateKey,
    path: str | os.PathLike[str],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Sign a file without loading the whole document into memory."""

    return sign_digest(private_key, sha256_file(path, chunk_size=chunk_size))


def verify_file(
    public_key: RSAPublicKey,
    path: str | os.PathLike[str],
    signature: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bool:
    """Verify a file, hashing it in fixed-size chunks."""

    return verify_digest(public_key, sha256_file(path, chunk_size=chunk_size), signature)
