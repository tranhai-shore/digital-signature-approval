"""Tests for the ``.sig`` package model and JSON schema."""

from __future__ import annotations

import json

import pytest

from src.models.signature_package import (
    PACKAGE_FORMAT,
    SIGNATURE_ALGORITHM,
    PackageError,
    SignaturePackage,
)

DIGEST = bytes(range(32))
SIGNATURE = bytes([0x42]) * 256


def make_package(**overrides: object) -> SignaturePackage:
    values = {
        "signer": "alice",
        "key_fingerprint": "sha256:" + "a" * 64,
        "original_name": "contract.pdf",
        "size": 1234,
        "signed_at": "2026-11-11T10:00:00Z",
        "file_digest": DIGEST,
        "signature": SIGNATURE,
    }
    values.update(overrides)
    return SignaturePackage(**values)  # type: ignore[arg-type]


def test_roundtrip_through_dict_and_json() -> None:
    package = make_package()
    data = package.to_dict()

    assert data["format"] == PACKAGE_FORMAT
    assert data["algorithm"] == SIGNATURE_ALGORITHM
    assert data["file"]["sha256"] == DIGEST.hex()

    restored = SignaturePackage.from_dict(data)
    assert restored == package
    assert SignaturePackage.from_json(package.to_json()) == package


def test_json_is_utf8_and_preserves_vietnamese() -> None:
    package = make_package(signer="Nguyễn Văn A", original_name="hợp_đồng.pdf")
    text = package.to_json()

    assert "Nguyễn Văn A" in text
    assert "hợp_đồng.pdf" in text
    assert json.loads(text)["signer"] == "Nguyễn Văn A"


def test_timestamp_and_unicode_are_canonicalised() -> None:
    package = make_package(
        signer="  Nguyễn Văn A  ",
        signed_at="2026-11-11T17:00:00+07:00",
    )
    assert package.signer == "Nguyễn Văn A"
    assert package.signed_at == "2026-11-11T10:00:00Z"


def test_file_sha256_property() -> None:
    assert make_package().file_sha256 == DIGEST.hex()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda d: d.pop("format"), "format"),
        (lambda d: d.update(format="DSIG/999"), "format"),
        (lambda d: d.update(algorithm="RSA-SHA1"), "algorithm"),
        (lambda d: d.update(signer=""), "signer"),
        (lambda d: d.update(key_fingerprint="sha256:abc"), "fingerprint"),
        (lambda d: d.update(signed_at="2026-11-11T10:00:00"), "signed_at"),
        (lambda d: d["file"].update(original_name="../x"), "basename"),
        (lambda d: d["file"].update(sha256="A" * 64), "sha256"),
        (lambda d: d["file"].update(size=True), "size"),
        (lambda d: d["file"].update(size=-1), "size"),
        (lambda d: d.update(signature="not valid base64!"), "signature"),
        (lambda d: d.update(signature=""), "signature"),
    ],
)
def test_malformed_packages_are_rejected(mutation, message: str) -> None:
    data = make_package().to_dict()
    mutation(data)
    with pytest.raises(PackageError, match=message):
        SignaturePackage.from_dict(data)


def test_unsupported_format_and_algorithm_are_rejected() -> None:
    with pytest.raises(PackageError):
        make_package(format="DSIG/999")
    with pytest.raises(PackageError):
        make_package(algorithm="RSA-SHA1")


def test_wrong_digest_length_is_rejected() -> None:
    with pytest.raises(PackageError):
        make_package(file_digest=b"\x00" * 31)


def test_empty_signature_is_rejected() -> None:
    with pytest.raises(PackageError):
        make_package(signature=b"")


def test_non_object_json_is_rejected() -> None:
    with pytest.raises(PackageError):
        SignaturePackage.from_json("[]")
    with pytest.raises(PackageError):
        SignaturePackage.from_json("not json")


def test_package_does_not_serialize_private_key_material() -> None:
    text = make_package().to_json()
    for forbidden in ("private", '"d"', '"p"', '"q"', "dp", "dq", "qinv"):
        assert forbidden not in text
