"""End-to-end tests for signing, package metadata binding and verification."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from src.crypto.rsa import generate_keypair
from src.models.signature_package import PackageError, SignaturePackage
from src.models.verification import VerificationReason
from src.services.package_service import read_package
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

FIXED_TIME = "2026-11-11T10:00:00Z"


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(bits=1024, rounds=24)


@pytest.fixture(scope="module")
def other_keypair():
    return generate_keypair(bits=1024, rounds=24)


def make_signed_file(tmp_path, keypair, *, data: bytes = b"contract data", name: str = "contract.pdf"):
    document = tmp_path / name
    document.write_bytes(data)
    result = SignService.sign_file(
        keypair,
        document,
        "alice",
        signed_at=FIXED_TIME,
    )
    return document, result


def test_sign_file_default_output_and_verify(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)

    assert result.package_path == document.with_name(document.name + ".sig")
    assert result.package_path.exists()
    assert read_package(result.package_path) == result.package

    verification = VerifyService.verify_file(
        document,
        result.package_path,
        keypair.public_key,
    )
    assert verification.valid
    assert bool(verification)
    assert verification.reason is VerificationReason.VALID
    assert verification.signer == "alice"
    assert verification.original_name == "contract.pdf"
    assert verification.signed_at == FIXED_TIME
    assert verification.key_fingerprint == keypair.public_key.fingerprint

    data = verification.as_dict()
    assert data["valid"] is True
    assert data["reason"] == "VALID"


def test_verify_with_package_object(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    verification = VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
    )
    assert verification.valid


def test_verify_data_roundtrip(keypair) -> None:
    data = b"in-memory contract"
    package = SignService.sign_data(
        keypair,
        data,
        "alice",
        "contract.txt",
        signed_at=FIXED_TIME,
    )

    assert VerifyService.verify_data(data, package, keypair.public_key).valid

    same_length_tamper = data[:-1] + b"X"
    result = VerifyService.verify_data(
        same_length_tamper,
        package,
        keypair.public_key,
    )
    assert result.reason is VerificationReason.HASH_MISMATCH

    result = VerifyService.verify_data(
        data + b"extra",
        package,
        keypair.public_key,
    )
    assert result.reason is VerificationReason.SIZE_MISMATCH


def test_one_bit_change_is_detected(tmp_path, keypair) -> None:
    data = b"payment amount: 1000 USD"
    document, result = make_signed_file(tmp_path, keypair, data=data)

    tampered = bytearray(data)
    tampered[0] ^= 0x01
    document.write_bytes(tampered)

    verification = VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
    )
    assert not verification
    assert verification.reason is VerificationReason.HASH_MISMATCH


def test_size_change_is_detected(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    document.write_bytes(document.read_bytes() + b"!")

    verification = VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.SIZE_MISMATCH


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signer", "mallory"),
        ("original_name", "other.pdf"),
        ("signed_at", "2026-11-11T10:00:01Z"),
    ],
)
def test_metadata_tamper_breaks_tbs(tmp_path, keypair, field: str, value: str) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    data = result.package.to_dict()
    if field == "original_name":
        data["file"]["original_name"] = value  # type: ignore[index]
    else:
        data[field] = value
    tampered_package = SignaturePackage.from_dict(data)

    verification = VerifyService.verify_file(
        document,
        tampered_package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.TBS_MISMATCH


def test_file_digest_tamper_is_detected(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    data = result.package.to_dict()
    data["file"]["sha256"] = "0" * 64  # type: ignore[index]
    tampered_package = SignaturePackage.from_dict(data)

    verification = VerifyService.verify_file(
        document,
        tampered_package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.HASH_MISMATCH


def test_size_metadata_tamper_is_detected(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    data = result.package.to_dict()
    data["file"]["size"] = int(data["file"]["size"]) + 1  # type: ignore[index]
    tampered_package = SignaturePackage.from_dict(data)

    verification = VerifyService.verify_file(
        document,
        tampered_package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.SIZE_MISMATCH


def test_wrong_public_key_is_rejected(tmp_path, keypair, other_keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    verification = VerifyService.verify_file(
        document,
        result.package,
        other_keypair.public_key,
    )
    assert verification.reason is VerificationReason.KEY_MISMATCH


def test_tampered_fingerprint_is_rejected(tmp_path, keypair, other_keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    package = replace(
        result.package,
        key_fingerprint=other_keypair.public_key.fingerprint,
    )
    verification = VerifyService.verify_file(
        document,
        package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.KEY_MISMATCH


def test_expected_signer(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)

    assert VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
        expected_signer="alice",
    ).valid

    verification = VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
        expected_signer="bob",
    )
    assert verification.reason is VerificationReason.SIGNER_MISMATCH


def test_invalid_expected_signer_raises(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    with pytest.raises(ValueError):
        VerifyService.verify_file(
            document,
            result.package,
            keypair.public_key,
            expected_signer="",
        )


def test_wrong_length_signature_is_malformed(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    package = replace(result.package, signature=result.package.signature[:-1])

    verification = VerifyService.verify_file(
        document,
        package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.SIGNATURE_MALFORMED


def test_zero_signature_has_invalid_padding(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    modulus_len = (keypair.n.bit_length() + 7) // 8
    package = replace(result.package, signature=b"\x00" * modulus_len)

    verification = VerifyService.verify_file(
        document,
        package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.PADDING_INVALID


def test_out_of_range_signature_is_malformed(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    modulus_len = (keypair.n.bit_length() + 7) // 8
    package = replace(result.package, signature=b"\xff" * modulus_len)

    verification = VerifyService.verify_file(
        document,
        package,
        keypair.public_key,
    )
    assert verification.reason in {
        VerificationReason.SIGNATURE_MALFORMED,
        VerificationReason.PADDING_INVALID,
    }


def test_bit_flipped_signature_is_rejected(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    signature = bytearray(result.package.signature)
    signature[len(signature) // 2] ^= 0x01
    package = replace(result.package, signature=bytes(signature))

    verification = VerifyService.verify_file(
        document,
        package,
        keypair.public_key,
    )
    assert not verification
    assert verification.reason in {
        VerificationReason.PADDING_INVALID,
        VerificationReason.SIGNATURE_MALFORMED,
        VerificationReason.TBS_MISMATCH,
    }


def test_missing_package_is_reported(tmp_path, keypair) -> None:
    document, _ = make_signed_file(tmp_path, keypair)
    verification = VerifyService.verify_file(
        document,
        tmp_path / "missing.sig",
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.PACKAGE_NOT_FOUND


@pytest.mark.parametrize("content", ["{not json", "[]", ""])
def test_malformed_package_is_reported(tmp_path, keypair, content: str) -> None:
    document, _ = make_signed_file(tmp_path, keypair)
    malformed = tmp_path / "bad.sig"
    malformed.write_text(content, encoding="utf-8")

    verification = VerifyService.verify_file(
        document,
        malformed,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.PACKAGE_MALFORMED


def test_non_utf8_package_is_reported(tmp_path, keypair) -> None:
    document, _ = make_signed_file(tmp_path, keypair)
    malformed = tmp_path / "bad.sig"
    malformed.write_bytes(b"\xff\xfe\x00")

    verification = VerifyService.verify_file(
        document,
        malformed,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.PACKAGE_MALFORMED


def test_unsupported_algorithm_is_reported(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    data = result.package.to_dict()
    data["algorithm"] = "RSA-SHA1"
    unsupported = tmp_path / "unsupported.sig"
    unsupported.write_text(json.dumps(data), encoding="utf-8")

    verification = VerifyService.verify_file(
        document,
        unsupported,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.UNSUPPORTED_ALGORITHM


def test_unreadable_package_path_is_reported(tmp_path, keypair) -> None:
    document, _ = make_signed_file(tmp_path, keypair)
    directory = tmp_path / "package.sig"
    directory.mkdir()

    verification = VerifyService.verify_file(
        document,
        directory,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.PACKAGE_READ_ERROR


def test_missing_document_is_reported(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    document.unlink()

    verification = VerifyService.verify_file(
        document,
        result.package,
        keypair.public_key,
    )
    assert verification.reason is VerificationReason.FILE_NOT_FOUND


def test_unicode_filename_roundtrip(tmp_path, keypair) -> None:
    name = "Hợp đồng phê duyệt 2026.pdf"
    document, result = make_signed_file(tmp_path, keypair, name=name)

    assert result.package.original_name == name
    verification = VerifyService.verify_file(
        document,
        result.package_path,
        keypair.public_key,
    )
    assert verification.valid
    assert verification.original_name == name


def test_custom_output_path_and_no_temporary_files(tmp_path, keypair) -> None:
    document = tmp_path / "contract.pdf"
    document.write_bytes(b"data")
    output = tmp_path / "packages" / "contract.sig"

    result = SignService.sign_file(
        keypair,
        document,
        "alice",
        output_path=output,
        signed_at=FIXED_TIME,
    )
    assert result.package_path == output
    assert output.exists()
    assert list(tmp_path.rglob("*.tmp")) == []


def test_sign_missing_document_raises(tmp_path, keypair) -> None:
    with pytest.raises(FileNotFoundError):
        SignService.sign_file(
            keypair,
            tmp_path / "missing.pdf",
            "alice",
        )


def test_sign_data_rejects_path_traversal_name(keypair) -> None:
    with pytest.raises(PackageError):
        SignService.sign_data(
            keypair,
            b"data",
            "alice",
            "../escape.pdf",
        )


def test_verify_data_rejects_non_bytes(tmp_path, keypair) -> None:
    document, result = make_signed_file(tmp_path, keypair)
    with pytest.raises(TypeError):
        VerifyService.verify_data(  # type: ignore[arg-type]
            "not bytes",
            result.package,
            keypair.public_key,
        )
