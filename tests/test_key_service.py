"""Tests for key generation, persistence and optional password protection."""

from __future__ import annotations

import json

import pytest

from src.crypto.encoding import b64url_decode, b64url_encode
from src.crypto.rsa import generate_keypair
from src.services.key_service import (
    ENCRYPTED_PRIVATE_FORMAT,
    KeyFileError,
    KeyService,
    validate_key_name,
)


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(bits=1024, rounds=24)


def test_generate_and_load_keypair(tmp_path) -> None:
    generated = KeyService.generate(
        "alice",
        bits=1024,
        keys_dir=tmp_path / "keys",
    )

    assert generated.private_path.exists()
    assert generated.public_path.exists()
    assert generated.fingerprint == generated.private_key.public_key.fingerprint

    loaded_private = KeyService.load_private(generated.private_path)
    loaded_public = KeyService.load_public(generated.public_path)

    assert loaded_private == generated.private_key
    assert loaded_public == generated.private_key.public_key
    assert loaded_public.fingerprint == generated.fingerprint

    envelope = json.loads(generated.private_path.read_text(encoding="utf-8"))
    assert envelope["format"] == "RSA-PRIV/1"


def test_save_and_load_existing_key(tmp_path, keypair) -> None:
    private_path = tmp_path / "alice_private.json"
    public_path = tmp_path / "alice_public.json"

    KeyService.save_private(keypair, private_path)
    KeyService.save_public(keypair.public_key, public_path)

    assert KeyService.load_private(private_path) == keypair
    assert KeyService.load_public(public_path) == keypair.public_key


def test_encrypted_private_key_roundtrip(tmp_path) -> None:
    pytest.importorskip("cryptography")
    key = generate_keypair(bits=1024, rounds=24)
    path = tmp_path / "alice_private.json"

    KeyService.save_private(key, path, password="correct horse battery staple")
    envelope = json.loads(path.read_text(encoding="utf-8"))

    assert envelope["format"] == ENCRYPTED_PRIVATE_FORMAT
    assert envelope["kdf"] == "PBKDF2-HMAC-SHA256"
    assert "d" not in envelope
    assert "p" not in envelope
    assert "q" not in envelope

    restored = KeyService.load_private(
        path,
        password="correct horse battery staple",
    )
    assert restored == key


def test_encrypted_key_requires_password(tmp_path) -> None:
    pytest.importorskip("cryptography")
    key = generate_keypair(bits=1024, rounds=24)
    path = tmp_path / "alice_private.json"
    KeyService.save_private(key, path, password="secret")

    with pytest.raises(KeyFileError, match="password"):
        KeyService.load_private(path)

    with pytest.raises(KeyFileError, match="wrong password"):
        KeyService.load_private(path, password="not-secret")


def test_tampered_encrypted_key_is_rejected(tmp_path) -> None:
    pytest.importorskip("cryptography")
    key = generate_keypair(bits=1024, rounds=24)
    path = tmp_path / "alice_private.json"
    KeyService.save_private(key, path, password="secret")

    envelope = json.loads(path.read_text(encoding="utf-8"))
    ciphertext = bytearray(b64url_decode(envelope["ciphertext"]))
    ciphertext[0] ^= 0x01
    envelope["ciphertext"] = b64url_encode(bytes(ciphertext))
    path.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(KeyFileError):
        KeyService.load_private(path, password="secret")


def test_missing_and_malformed_key_files(tmp_path) -> None:
    with pytest.raises(KeyFileError):
        KeyService.load_private(tmp_path / "missing.json")
    with pytest.raises(KeyFileError):
        KeyService.load_public(tmp_path / "missing.json")

    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(KeyFileError):
        KeyService.load_public(malformed)

    wrong_shape = tmp_path / "array.json"
    wrong_shape.write_text("[]", encoding="utf-8")
    with pytest.raises(KeyFileError):
        KeyService.load_private(wrong_shape)


def test_save_private_rejects_wrong_object(tmp_path) -> None:
    with pytest.raises(TypeError):
        KeyService.save_private("not a key", tmp_path / "key.json")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        KeyService.save_public("not a key", tmp_path / "key.json")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "name",
    ["alice", "team.alice-01", "A1", "x" * 64],
)
def test_valid_key_names(name: str) -> None:
    assert validate_key_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "../alice", "a/b", "a\\b", "alice!", " x", "x" * 65],
)
def test_invalid_key_names(name: str) -> None:
    with pytest.raises(ValueError):
        validate_key_name(name)
