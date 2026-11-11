"""Unit tests for byte/int and base64url encoding helpers."""

from __future__ import annotations

import pytest

from src.crypto.encoding import (
    b64url_decode,
    b64url_encode,
    bytes_to_int,
    constant_time_compare,
    int_to_bytes,
)


@pytest.mark.parametrize("value", [0, 1, 42, 255, 256, 2**64, 2**2048 - 1])
def test_int_byte_roundtrip(value: int) -> None:
    assert bytes_to_int(int_to_bytes(value)) == value


def test_int_to_bytes_uses_minimal_length_and_padding() -> None:
    assert int_to_bytes(0) == b"\x00"
    assert int_to_bytes(256) == b"\x01\x00"
    assert int_to_bytes(1, length=4) == b"\x00\x00\x00\x01"


def test_int_to_bytes_rejects_invalid_arguments() -> None:
    with pytest.raises(ValueError):
        int_to_bytes(-1)
    with pytest.raises(ValueError):
        int_to_bytes(1, length=0)


def test_base64url_roundtrip() -> None:
    payload = bytes(range(256))
    encoded = b64url_encode(payload)
    assert "=" not in encoded
    assert b64url_decode(encoded) == payload


def test_base64url_rejects_malformed_data() -> None:
    with pytest.raises(ValueError):
        b64url_decode("not valid base64!")


def test_constant_time_compare() -> None:
    assert constant_time_compare(b"abc", b"abc")
    assert not constant_time_compare(b"abc", b"abd")
    assert not constant_time_compare(b"abc", b"ab")
