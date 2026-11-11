"""Unit tests for the RSA core: key generation, raw sign and raw verify."""

from __future__ import annotations

import time

import pytest

from src.crypto.numtheory import gcd, modexp
from src.crypto.rsa import RSAPrivateKey, RSAPublicKey, generate_keypair


@pytest.fixture(scope="module")
def keypair() -> RSAPrivateKey:
    """A 1024-bit key shared by the functional tests (fast but still realistic)."""

    return generate_keypair(bits=1024, rounds=24)


@pytest.fixture(scope="module")
def toy_key() -> RSAPrivateKey:
    """Classic textbook RSA example: p=61, q=53, e=17, d=2753."""

    return RSAPrivateKey(n=3233, e=17, d=2753, p=61, q=53)


def test_keypair_parameters_are_consistent(keypair: RSAPrivateKey) -> None:
    assert keypair.key_size == 1024
    assert keypair.e == 65537
    assert keypair.p != keypair.q
    assert keypair.p * keypair.q == keypair.n
    phi = (keypair.p - 1) * (keypair.q - 1)
    assert (keypair.e * keypair.d) % phi == 1
    assert keypair.dp == keypair.d % (keypair.p - 1)
    assert keypair.dq == keypair.d % (keypair.q - 1)
    assert (keypair.q * keypair.qinv) % keypair.p == 1


def test_toy_key_matches_known_vector(toy_key: RSAPrivateKey) -> None:
    # Classic RSA example: p=61, q=53, e=17, d=2753, n=3233.
    # Encryption of m=65 gives 2790; the *signature* is 65^d mod n = 588.
    assert modexp(65, 17, 3233) == 2790
    signature = toy_key.sign_int(65)
    assert signature == 588
    assert toy_key.recover_int(signature) == 65
    assert toy_key.public_key.verify_int(65, signature)


def test_sign_and_recover_roundtrip(keypair: RSAPrivateKey) -> None:
    for message in (0, 1, 2, 42, 255, 256, 2**512, keypair.n - 1):
        signature = keypair.sign_int(message)
        assert 0 <= signature < keypair.n
        assert keypair.recover_int(signature) == message
        assert keypair.public_key.verify_int(message, signature)


def test_crt_signature_matches_plain_modexp(keypair: RSAPrivateKey) -> None:
    for message in (1, 42, 123456789, keypair.n - 2):
        assert keypair.sign_int(message) == modexp(message, keypair.d, keypair.n)


def test_tampered_signature_is_rejected(keypair: RSAPrivateKey) -> None:
    message = 42
    signature = keypair.sign_int(message)
    assert not keypair.public_key.verify_int(message, signature + 1)
    assert keypair.recover_int(signature + 1) != message


def test_signature_from_another_key_is_rejected(
    keypair: RSAPrivateKey, toy_key: RSAPrivateKey
) -> None:
    message = 42
    signature = toy_key.sign_int(message)
    assert not keypair.public_key.verify_int(message, signature)


def test_sign_and_recover_reject_out_of_range_values(
    keypair: RSAPrivateKey,
) -> None:
    with pytest.raises(ValueError):
        keypair.sign_int(-1)
    with pytest.raises(ValueError):
        keypair.sign_int(keypair.n)
    with pytest.raises(ValueError):
        keypair.recover_int(-1)
    with pytest.raises(ValueError):
        keypair.recover_int(keypair.n)


def test_verify_int_returns_false_for_out_of_range_inputs(
    keypair: RSAPrivateKey,
) -> None:
    assert not keypair.public_key.verify_int(-1, 2)
    assert not keypair.public_key.verify_int(keypair.n, 2)
    assert not keypair.public_key.verify_int(2, -1)
    assert not keypair.public_key.verify_int(2, keypair.n)


def test_public_key_fingerprint_is_stable_and_distinct(
    keypair: RSAPrivateKey, toy_key: RSAPrivateKey
) -> None:
    public = keypair.public_key
    assert public.fingerprint.startswith("sha256:")
    assert len(public.fingerprint) == len("sha256:") + 64
    assert public.fingerprint == keypair.public_key.fingerprint
    assert public.fingerprint != toy_key.public_key.fingerprint
    assert public.canonical_bytes() == keypair.public_key.canonical_bytes()


def test_public_key_serialisation_roundtrip(keypair: RSAPrivateKey) -> None:
    data = keypair.public_key.to_dict()
    restored = RSAPublicKey.from_dict(data)
    assert restored == keypair.public_key
    assert restored.fingerprint == keypair.public_key.fingerprint

    data["fingerprint"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        RSAPublicKey.from_dict(data)


def test_private_key_serialisation_roundtrip(keypair: RSAPrivateKey) -> None:
    data = keypair.to_dict()
    restored = RSAPrivateKey.from_dict(data)
    assert restored == keypair
    assert restored.public_key.fingerprint == keypair.public_key.fingerprint

    data["d"] = str(int(data["d"]) + 2)
    with pytest.raises(ValueError):
        RSAPrivateKey.from_dict(data)


def test_private_key_repr_does_not_leak_secrets(keypair: RSAPrivateKey) -> None:
    representation = repr(keypair)
    assert "RSAPrivateKey(" in representation
    assert "fingerprint=" in representation
    assert str(keypair.d) not in representation
    assert str(keypair.p) not in representation
    assert str(keypair.q) not in representation


def test_invalid_private_key_components_are_rejected(toy_key: RSAPrivateKey) -> None:
    with pytest.raises(ValueError):
        RSAPrivateKey(n=3233, e=17, d=2754, p=61, q=53)
    with pytest.raises(ValueError):
        RSAPrivateKey(n=3234, e=17, d=2753, p=61, q=53)
    with pytest.raises(ValueError):
        RSAPrivateKey(n=61 * 61, e=17, d=2753, p=61, q=61)


def test_keygen_rejects_invalid_sizes() -> None:
    with pytest.raises(ValueError):
        generate_keypair(bits=128)
    with pytest.raises(ValueError):
        generate_keypair(bits=512, e=4)


def test_keygen_2048_bit_meets_project_requirement() -> None:
    started = time.perf_counter()
    key = generate_keypair(bits=2048, rounds=40)
    elapsed = time.perf_counter() - started

    assert key.key_size == 2048
    assert gcd(key.e, (key.p - 1) * (key.q - 1)) == 1
    signature = key.sign_int(123456789)
    assert key.public_key.verify_int(123456789, signature)

    # Recorded for the report; generous bound to avoid flaky CI failures.
    assert elapsed < 15.0, f"2048-bit key generation took {elapsed:.2f}s"
