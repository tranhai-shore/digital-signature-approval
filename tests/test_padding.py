"""Unit tests for EMSA-PKCS1-v1_5 encoding with SHA-256."""

from __future__ import annotations

import pytest

from src.crypto.padding import (
    MIN_EM_LENGTH,
    SHA256_DIGEST_INFO,
    PaddingError,
    decode_pkcs1_v1_5,
    encode_pkcs1_v1_5,
)

DIGEST = bytes(range(32))


def _encoded(em_len: int = 256) -> bytes:
    return encode_pkcs1_v1_5(DIGEST, em_len)


def test_encoding_structure() -> None:
    em = _encoded()
    assert len(em) == 256
    assert em[:2] == b"\x00\x01"

    separator = em.find(b"\x00", 2)
    assert separator > 0
    assert separator - 2 >= 8
    assert em[2:separator] == b"\xff" * (separator - 2)
    assert em[separator + 1 :] == SHA256_DIGEST_INFO + DIGEST


def test_minimum_length_has_exactly_eight_padding_bytes() -> None:
    em = encode_pkcs1_v1_5(DIGEST, MIN_EM_LENGTH)
    separator = em.find(b"\x00", 2)
    assert separator == 10
    assert len(em) == MIN_EM_LENGTH


def test_encoding_is_deterministic() -> None:
    assert _encoded() == _encoded()


def test_decode_roundtrip() -> None:
    assert decode_pkcs1_v1_5(_encoded()) == DIGEST


@pytest.mark.parametrize("em_len", [MIN_EM_LENGTH, 128, 256, 384])
def test_roundtrip_for_several_modulus_sizes(em_len: int) -> None:
    assert decode_pkcs1_v1_5(encode_pkcs1_v1_5(DIGEST, em_len)) == DIGEST


def test_invalid_digest_length_is_rejected() -> None:
    with pytest.raises(ValueError):
        encode_pkcs1_v1_5(b"\x00" * 31, 256)
    with pytest.raises(ValueError):
        encode_pkcs1_v1_5(b"\x00" * 33, 256)


def test_encoded_message_too_short_is_rejected() -> None:
    with pytest.raises(ValueError):
        encode_pkcs1_v1_5(DIGEST, MIN_EM_LENGTH - 1)


def _assert_invalid(em: bytes | bytearray) -> None:
    with pytest.raises(PaddingError):
        decode_pkcs1_v1_5(bytes(em))


def test_tampered_header_is_rejected() -> None:
    em = bytearray(_encoded())
    em[0] = 0x01
    _assert_invalid(em)

    em = bytearray(_encoded())
    em[1] = 0x02
    _assert_invalid(em)


def test_tampered_padding_is_rejected() -> None:
    em = bytearray(_encoded())
    em[2] = 0x00
    _assert_invalid(em)

    em = bytearray(_encoded())
    em[2] = 0xFE
    _assert_invalid(em)


def test_missing_separator_is_rejected() -> None:
    em = bytearray(_encoded())
    separator = em.find(b"\x00", 2)
    em[separator] = 0x01
    _assert_invalid(em)


def test_tampered_digest_info_is_rejected() -> None:
    em = bytearray(_encoded())
    separator = em.find(b"\x00", 2)
    em[separator + 1] ^= 0x01
    _assert_invalid(em)


def test_tampered_digest_is_returned_for_caller_comparison() -> None:
    # Structural decoding cannot know which digest is expected; the signature
    # verifier must compare the returned digest with the recomputed one.
    em = bytearray(_encoded())
    em[-1] ^= 0x01

    recovered = decode_pkcs1_v1_5(bytes(em))
    assert len(recovered) == 32
    assert recovered != DIGEST


def test_truncated_and_oversized_blocks_are_rejected() -> None:
    _assert_invalid(_encoded()[:-1])
    _assert_invalid(b"\x00" * 256)
    _assert_invalid(b"")


def test_all_zero_padding_string_is_rejected() -> None:
    em = b"\x00\x01" + (b"\x00" * 8) + b"\x00" + SHA256_DIGEST_INFO + DIGEST
    _assert_invalid(em)
