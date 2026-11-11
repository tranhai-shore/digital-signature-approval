"""Integration tests for the safe signing API (SHA-256 + PKCS#1 v1.5)."""

from __future__ import annotations

import pytest

from src.crypto.hashing import sha256_bytes
from src.crypto.padding import PaddingError
from src.crypto.rsa import RSAPrivateKey, generate_keypair
from src.crypto.signature import (
    SignatureFormatError,
    recover_digest,
    sign_bytes,
    sign_digest,
    sign_file,
    verify_bytes,
    verify_digest,
    verify_file,
)


@pytest.fixture(scope="module")
def keypair() -> RSAPrivateKey:
    return generate_keypair(bits=1024, rounds=24)


@pytest.fixture(scope="module")
def other_keypair() -> RSAPrivateKey:
    return generate_keypair(bits=1024, rounds=24)


def test_sign_and_verify_bytes(keypair: RSAPrivateKey) -> None:
    data = "Hợp đồng phê duyệt số 42 — số tiền 1.000 USD".encode()
    signature = sign_bytes(keypair, data)

    assert len(signature) == 128
    assert verify_bytes(keypair.public_key, data, signature)
    assert not verify_bytes(keypair.public_key, data + b" ", signature)
    assert not verify_bytes(keypair.public_key, data[:-1], signature)


def test_signature_is_deterministic(keypair: RSAPrivateKey) -> None:
    data = b"deterministic PKCS#1 v1.5 signature"
    assert sign_bytes(keypair, data) == sign_bytes(keypair, data)


def test_digest_api_and_recovery(keypair: RSAPrivateKey) -> None:
    data = b"digest-level API"
    digest = sha256_bytes(data)
    signature = sign_digest(keypair, digest)

    assert recover_digest(keypair.public_key, signature) == digest
    assert verify_digest(keypair.public_key, digest, signature)
    assert not verify_digest(keypair.public_key, sha256_bytes(data + b"!"), signature)


def test_tampered_signature_is_rejected(keypair: RSAPrivateKey) -> None:
    data = b"tamper test"
    signature = sign_bytes(keypair, data)

    for index in (0, 1, len(signature) // 2, len(signature) - 1):
        tampered = bytearray(signature)
        tampered[index] ^= 0x01
        assert not verify_digest(
            keypair.public_key, sha256_bytes(data), bytes(tampered)
        )


def test_wrong_public_key_is_rejected(
    keypair: RSAPrivateKey, other_keypair: RSAPrivateKey
) -> None:
    data = b"wrong key test"
    signature = sign_bytes(keypair, data)
    assert not verify_bytes(other_keypair.public_key, data, signature)


def test_wrong_length_signature_is_rejected(keypair: RSAPrivateKey) -> None:
    data = b"length test"
    digest = sha256_bytes(data)
    signature = sign_digest(keypair, digest)

    assert not verify_digest(keypair.public_key, digest, signature[:-1])
    assert not verify_digest(keypair.public_key, digest, signature + b"\x00")

    with pytest.raises(SignatureFormatError):
        recover_digest(keypair.public_key, signature[:-1])


def test_out_of_range_signature_is_rejected(keypair: RSAPrivateKey) -> None:
    digest = sha256_bytes(b"range test")
    modulus_len = (keypair.n.bit_length() + 7) // 8

    assert not verify_digest(keypair.public_key, digest, b"\x00" * modulus_len)
    assert not verify_digest(keypair.public_key, digest, b"\xff" * modulus_len)

    with pytest.raises(SignatureFormatError):
        recover_digest(keypair.public_key, b"\xff" * modulus_len)


def test_invalid_padding_is_rejected(keypair: RSAPrivateKey) -> None:
    modulus_len = (keypair.n.bit_length() + 7) // 8
    with pytest.raises(PaddingError):
        recover_digest(keypair.public_key, b"\x00" * modulus_len)


def test_digest_length_is_validated(keypair: RSAPrivateKey) -> None:
    with pytest.raises(ValueError):
        sign_digest(keypair, b"\x00" * 31)
    with pytest.raises(ValueError):
        verify_digest(keypair.public_key, b"\x00" * 31, b"\x00" * 128)


def test_empty_document_can_be_signed(keypair: RSAPrivateKey) -> None:
    signature = sign_bytes(keypair, b"")
    assert verify_bytes(keypair.public_key, b"", signature)
    assert not verify_bytes(keypair.public_key, b"x", signature)


def test_file_signing_and_tamper_detection(
    keypair: RSAPrivateKey, tmp_path
) -> None:
    payload = (b"approval-record-2026-" * 80_000) + b"END"
    original = tmp_path / "contract.pdf"
    original.write_bytes(payload)

    signature = sign_file(keypair, original, chunk_size=4096)
    assert verify_file(keypair.public_key, original, signature, chunk_size=777)

    tampered_payload = bytearray(payload)
    tampered_payload[123_456] ^= 0x01
    tampered = tmp_path / "contract_tampered.pdf"
    tampered.write_bytes(tampered_payload)

    assert not verify_file(keypair.public_key, tampered, signature, chunk_size=4096)


def test_too_small_modulus_cannot_carry_sha256_padding() -> None:
    toy_key = RSAPrivateKey(n=3233, e=17, d=2753, p=61, q=53)
    with pytest.raises(ValueError):
        sign_digest(toy_key, b"\x00" * 32)
    assert not verify_digest(toy_key.public_key, b"\x00" * 32, b"\x00\x00")


def test_2048_bit_document_signature_roundtrip() -> None:
    key = generate_keypair(bits=2048)
    data = b"hop dong 2048-bit"
    signature = sign_bytes(key, data)

    assert len(signature) == 256
    assert verify_bytes(key.public_key, data, signature)
    assert not verify_bytes(key.public_key, data + b"!", signature)


def test_cross_check_with_cryptography(keypair: RSAPrivateKey) -> None:
    """Our signatures must be byte-identical to a widely used implementation."""

    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa

    public_numbers = crypto_rsa.RSAPublicNumbers(e=keypair.e, n=keypair.n)
    crypto_public = public_numbers.public_key()
    private_numbers = crypto_rsa.RSAPrivateNumbers(
        p=keypair.p,
        q=keypair.q,
        d=keypair.d,
        dmp1=keypair.dp,
        dmq1=keypair.dq,
        iqmp=keypair.qinv,
        public_numbers=public_numbers,
    )
    crypto_private = private_numbers.private_key()

    data = b"cross-implementation compatibility check"
    our_signature = sign_bytes(keypair, data)
    crypto_signature = crypto_private.sign(
        data,
        crypto_padding.PKCS1v15(),
        hashes.SHA256(),
    )

    assert our_signature == crypto_signature
    assert (
        crypto_public.verify(
            our_signature,
            data,
            crypto_padding.PKCS1v15(),
            hashes.SHA256(),
        )
        is None
    )
    assert verify_bytes(keypair.public_key, data, crypto_signature)
