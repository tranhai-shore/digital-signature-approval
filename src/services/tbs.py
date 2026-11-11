"""Canonical TBS (to-be-signed) construction.

The TBS binds the signature to all approval metadata, not only to the document
bytes.  Every variable-length field is length-prefixed, which prevents
ambiguity attacks such as ``("ab", "c")`` versus ``("a", "bc")``.

Layout (all integers big-endian)::

    b"DSIGv1\\x00"
    || u32(len(algorithm)) || algorithm_utf8
    || u32(len(signer))    || signer_utf8
    || u32(len(name))      || original_name_utf8
    || u64(size)
    || u32(len(signed_at)) || signed_at_utf8
    || file_sha256 (32 bytes)
"""

from __future__ import annotations

from src.models.signature_package import (
    SIGNATURE_ALGORITHM,
    normalize_original_name,
    normalize_signer,
)
from src.models.timestamp import canonicalize_timestamp

TBS_DOMAIN = b"DSIGv1\x00"
SHA256_SIZE = 32


def _length_prefixed(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) >= 2**32:
        raise ValueError("TBS field is too large")
    return len(encoded).to_bytes(4, "big") + encoded


def build_tbs(
    *,
    algorithm: str,
    signer: str,
    original_name: str,
    size: int,
    signed_at: str,
    file_digest: bytes,
) -> bytes:
    """Build the canonical byte string that is actually signed."""

    if algorithm != SIGNATURE_ALGORITHM:
        raise ValueError(f"unsupported signature algorithm: {algorithm!r}")
    if isinstance(size, bool) or not isinstance(size, int):
        raise ValueError("size must be an integer")
    if size < 0 or size >= 2**64:
        raise ValueError("size must be between 0 and 2^64 - 1")
    if not isinstance(file_digest, bytes) or len(file_digest) != SHA256_SIZE:
        raise ValueError("file_digest must be a 32-byte SHA-256 digest")

    canonical_signer = normalize_signer(signer)
    canonical_name = normalize_original_name(original_name)
    canonical_time = canonicalize_timestamp(signed_at)

    return b"".join(
        (
            TBS_DOMAIN,
            _length_prefixed(algorithm),
            _length_prefixed(canonical_signer),
            _length_prefixed(canonical_name),
            size.to_bytes(8, "big"),
            _length_prefixed(canonical_time),
            file_digest,
        )
    )
