"""Byte/int encoding helpers shared by the crypto modules."""

from __future__ import annotations

import base64
import binascii
import hmac


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    """Encode a non-negative integer as a big-endian byte string.

    ``value == 0`` is encoded as a single zero byte unless ``length`` is given.
    """

    if value < 0:
        raise ValueError("value must be non-negative")

    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    elif length <= 0:
        raise ValueError("length must be positive")

    return value.to_bytes(length, "big")


def bytes_to_int(data: bytes) -> int:
    """Decode a big-endian byte string into a non-negative integer."""

    return int.from_bytes(data, "big")


def b64url_encode(data: bytes) -> str:
    """Return unpadded URL-safe base64 (suitable for JSON signature files)."""

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str | bytes) -> bytes:
    """Decode unpadded URL-safe base64, rejecting malformed input."""

    if isinstance(text, str):
        raw = text.encode("ascii")
    else:
        raw = text

    raw += b"=" * (-len(raw) % 4)
    try:
        return base64.b64decode(raw, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url data") from exc


def constant_time_compare(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without leaking their first difference."""

    return hmac.compare_digest(left, right)
