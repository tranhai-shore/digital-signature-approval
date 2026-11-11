"""Hardening tests: strict JSON, fuzzing, limits and large documents."""

from __future__ import annotations

import json
import random
import unicodedata
from pathlib import Path

import pytest

from src.crypto.rsa import RSAPrivateKey, generate_keypair
from src.models import json_support
from src.models.json_support import (
    DEFAULT_MAX_JSON_BYTES,
    MAX_JSON_INTEGER_DIGITS,
    JSONSupportError,
    loads_strict,
    read_json_file,
)
from src.models.signature_package import (
    MAX_ORIGINAL_NAME_CHARACTERS,
    MAX_SIGNER_CHARACTERS,
    PackageError,
    SignaturePackage,
)
from src.models.timestamp import MAX_TIMESTAMP_CHARACTERS, canonicalize_timestamp
from src.models.verification import VerificationReason
from src.services.key_service import KeyFileError, KeyService
from src.services.package_service import read_package
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

FIXED_TIME = "2026-11-11T10:00:00Z"
DIGEST = bytes(range(32))
SIGNATURE = b"\x42" * 128


@pytest.fixture(scope="module")
def keypair() -> RSAPrivateKey:
    return generate_keypair(bits=1024, rounds=24)


def make_package(**overrides: object) -> SignaturePackage:
    values = {
        "signer": "alice",
        "key_fingerprint": "sha256:" + "a" * 64,
        "original_name": "contract.pdf",
        "size": 1234,
        "signed_at": FIXED_TIME,
        "file_digest": DIGEST,
        "signature": SIGNATURE,
    }
    values.update(overrides)
    return SignaturePackage(**values)  # type: ignore[arg-type]


def write_package_text(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Strict JSON loader
# ---------------------------------------------------------------------------


def test_loads_strict_accepts_valid_json() -> None:
    value = loads_strict('{"a": 1, "b": [true, null, "x"]}')
    assert value == {"a": 1, "b": [True, None, "x"]}


@pytest.mark.parametrize(
    "text",
    [
        '{"a": 1, "a": 2}',
        '{"outer": {"x": 1, "x": 2}}',
        '{"a": 1, "b": 2, "a": 3}',
    ],
)
def test_loads_strict_rejects_duplicate_keys(text: str) -> None:
    with pytest.raises(JSONSupportError, match="duplicate"):
        loads_strict(text)


@pytest.mark.parametrize(
    "text",
    [
        '{"v": NaN}',
        '{"v": Infinity}',
        '{"v": -Infinity}',
        '{"v": 1e99999}',
    ],
)
def test_loads_strict_rejects_non_finite_numbers(text: str) -> None:
    with pytest.raises(JSONSupportError, match="non-finite"):
        loads_strict(text)


def test_loads_strict_rejects_oversized_integers() -> None:
    text = '{"n": ' + "9" * (MAX_JSON_INTEGER_DIGITS + 1) + "}"

    with pytest.raises(JSONSupportError, match="integer"):
        loads_strict(text)


@pytest.mark.parametrize("payload", [b"", b"not json", b'{"a": }'])
def test_loads_strict_wraps_json_syntax_errors(payload: bytes) -> None:
    with pytest.raises(JSONSupportError, match="not valid"):
        loads_strict(payload)


def test_loads_strict_rejects_invalid_utf8() -> None:
    with pytest.raises(JSONSupportError, match="UTF-8"):
        loads_strict(b"\xff\xfe\x00")


def test_loads_strict_rejects_oversized_input() -> None:
    with pytest.raises(JSONSupportError, match="limit"):
        loads_strict(" " * (DEFAULT_MAX_JSON_BYTES + 1))
    with pytest.raises(JSONSupportError, match="limit"):
        loads_strict(b" " * (DEFAULT_MAX_JSON_BYTES + 1))


def test_loads_strict_rejects_non_text_input() -> None:
    with pytest.raises(TypeError):
        loads_strict(123)  # type: ignore[arg-type]


def test_loads_strict_wraps_recursion_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_recursion(*args: object, **kwargs: object) -> object:
        raise RecursionError("too deep")

    monkeypatch.setattr(json_support.json, "loads", raise_recursion)
    with pytest.raises(JSONSupportError, match="nesting"):
        json_support.loads_strict("{}")


def test_read_json_file_enforces_size_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b" " * (DEFAULT_MAX_JSON_BYTES + 1))

    with pytest.raises(JSONSupportError, match="limit"):
        read_json_file(path)


def test_read_json_file_parses_valid_object(tmp_path: Path) -> None:
    path = tmp_path / "data.json"
    path.write_text('{"ok": true}', encoding="utf-8")

    assert read_json_file(path) == {"ok": True}


# ---------------------------------------------------------------------------
# Package-level strictness
# ---------------------------------------------------------------------------


def test_read_package_rejects_duplicate_keys(tmp_path: Path) -> None:
    package = make_package()
    text = package.to_json()[:-1] + ',\n  "signer": "mallory"\n}'
    path = write_package_text(tmp_path / "duplicate.sig", text)

    with pytest.raises(PackageError, match="duplicate"):
        read_package(path)


def test_read_package_rejects_non_finite_values(tmp_path: Path) -> None:
    package = make_package()
    text = package.to_json().replace(
        f'"size": {package.size}',
        '"size": NaN',
        1,
    )
    path = write_package_text(tmp_path / "nan.sig", text)

    with pytest.raises(PackageError, match="non-finite"):
        read_package(path)


def test_read_package_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "big.sig"
    path.write_bytes(b" " * (DEFAULT_MAX_JSON_BYTES + 1))

    with pytest.raises(PackageError, match="limit"):
        read_package(path)


def test_from_json_rejects_oversized_text() -> None:
    with pytest.raises(PackageError, match="limit"):
        SignaturePackage.from_json(" " * (DEFAULT_MAX_JSON_BYTES + 1))


def test_from_json_rejects_lone_surrogate_escape() -> None:
    data = make_package().to_dict()
    data["signer"] = "\ud800"
    text = json.dumps(data)

    with pytest.raises(PackageError, match="Unicode"):
        SignaturePackage.from_json(text)


def test_from_json_accepts_unknown_fields() -> None:
    data = make_package().to_dict()
    data["future_extension"] = {"note": "ignored"}

    assert SignaturePackage.from_dict(data) == make_package()


# ---------------------------------------------------------------------------
# Metadata length limits
# ---------------------------------------------------------------------------


def test_signer_length_limit() -> None:
    accepted = make_package(signer="a" * MAX_SIGNER_CHARACTERS)
    assert len(accepted.signer) == MAX_SIGNER_CHARACTERS

    with pytest.raises(PackageError, match="signer"):
        make_package(signer="a" * (MAX_SIGNER_CHARACTERS + 1))


def test_original_name_length_limit() -> None:
    accepted = make_package(original_name="a" * MAX_ORIGINAL_NAME_CHARACTERS)
    assert len(accepted.original_name) == MAX_ORIGINAL_NAME_CHARACTERS

    with pytest.raises(PackageError, match="original_name"):
        make_package(
            original_name="a" * (MAX_ORIGINAL_NAME_CHARACTERS + 1)
        )


def test_timestamp_length_limit() -> None:
    assert canonicalize_timestamp(FIXED_TIME) == FIXED_TIME

    oversized = "2026-11-11T10:00:00Z" + "0" * MAX_TIMESTAMP_CHARACTERS
    with pytest.raises(ValueError, match="too long"):
        canonicalize_timestamp(oversized)


def test_sign_service_rejects_oversized_signer(tmp_path: Path, keypair) -> None:
    document = tmp_path / "contract.txt"
    document.write_bytes(b"data")

    with pytest.raises(PackageError, match="signer"):
        SignService.sign_file(
            keypair,
            document,
            "a" * (MAX_SIGNER_CHARACTERS + 1),
        )

    assert not document.with_name(document.name + ".sig").exists()


# ---------------------------------------------------------------------------
# Unicode edge cases
# ---------------------------------------------------------------------------


def test_unicode_metadata_roundtrip(tmp_path: Path, keypair) -> None:
    name = "Hợp-đồng-phê-duyệt-2026.pdf"
    signer = "Nguyễn Văn Ánh ✅"
    data = "nội dung phê duyệt — 承認 ✅".encode("utf-8")
    document = tmp_path / name
    document.write_bytes(data)

    result = SignService.sign_file(
        keypair,
        document,
        signer,
        signed_at=FIXED_TIME,
    )

    assert result.package.signer == signer
    assert result.package.original_name == name
    assert read_package(result.package_path) == result.package
    verification = VerifyService.verify_file(
        document,
        result.package_path,
        keypair.public_key,
    )
    assert verification.valid
    assert verification.signer == signer


def test_nfd_signer_is_canonicalized_before_signing(keypair) -> None:
    nfc = "Nguyễn Văn Ánh"
    nfd = unicodedata.normalize("NFD", nfc)

    package = SignService.sign_data(keypair, b"data", nfd, "contract.txt")

    assert nfd != nfc
    assert package.signer == nfc
    assert VerifyService.verify_data(
        b"data",
        package,
        keypair.public_key,
        expected_signer=nfc,
    ).valid


# ---------------------------------------------------------------------------
# Document edge cases and large files
# ---------------------------------------------------------------------------


def test_empty_document_roundtrip(tmp_path: Path, keypair) -> None:
    document = tmp_path / "empty.txt"
    document.write_bytes(b"")

    result = SignService.sign_file(
        keypair,
        document,
        "alice",
        signed_at=FIXED_TIME,
    )

    assert result.package.size == 0
    assert result.package.file_digest.hex() == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
    assert VerifyService.verify_file(
        document,
        result.package_path,
        keypair.public_key,
    ).valid


def test_fifty_mib_document_is_streamed(tmp_path: Path, keypair) -> None:
    document = tmp_path / "large.bin"
    size = 50 * 1024 * 1024
    with document.open("wb") as handle:
        handle.truncate(size)

    result = SignService.sign_file(
        keypair,
        document,
        "alice",
        signed_at=FIXED_TIME,
    )

    assert result.package.size == size
    verification = VerifyService.verify_file(
        document,
        result.package_path,
        keypair.public_key,
    )
    assert verification.valid


# ---------------------------------------------------------------------------
# Malformed-input fuzzing
# ---------------------------------------------------------------------------


def test_random_json_text_only_raises_package_error() -> None:
    rng = random.Random(20261111)
    alphabet = (
        '{}[]":,0123456789abcdefghijklmnopqrstuvwxyz '
        "\n\t-_.+/é中✅"
    )

    for _ in range(500):
        length = rng.randrange(0, 96)
        text = "".join(rng.choice(alphabet) for _ in range(length))
        try:
            SignaturePackage.from_json(text)
        except PackageError:
            pass


def test_random_package_bytes_never_crash_verification(
    tmp_path: Path,
    keypair,
) -> None:
    document = tmp_path / "contract.txt"
    document.write_bytes(b"contract data")
    package_path = tmp_path / "fuzz.sig"
    rng = random.Random(7)

    for _ in range(200):
        length = rng.randrange(0, 400)
        package_path.write_bytes(
            bytes(rng.randrange(256) for _ in range(length))
        )
        result = VerifyService.verify_file(
            document,
            package_path,
            keypair.public_key,
        )
        assert result.valid is False
        assert isinstance(result.reason, VerificationReason)


def test_empty_package_is_reported_as_malformed(
    tmp_path: Path,
    keypair,
) -> None:
    document = tmp_path / "contract.txt"
    document.write_bytes(b"contract data")
    package_path = tmp_path / "empty.sig"
    package_path.write_bytes(b"")

    result = VerifyService.verify_file(
        document,
        package_path,
        keypair.public_key,
    )

    assert result.reason is VerificationReason.PACKAGE_MALFORMED


def test_oversized_package_is_reported_as_malformed(
    tmp_path: Path,
    keypair,
) -> None:
    document = tmp_path / "contract.txt"
    document.write_bytes(b"contract data")
    package_path = tmp_path / "big.sig"
    package_path.write_bytes(b" " * (DEFAULT_MAX_JSON_BYTES + 1))

    result = VerifyService.verify_file(
        document,
        package_path,
        keypair.public_key,
    )

    assert result.reason is VerificationReason.PACKAGE_MALFORMED


def test_mutated_packages_never_raise(tmp_path: Path, keypair) -> None:
    document = tmp_path / "contract.txt"
    document.write_bytes(b"contract data")
    signed = SignService.sign_file(
        keypair,
        document,
        "alice",
        signed_at=FIXED_TIME,
    )
    base = bytearray(signed.package_path.read_bytes())
    package_path = tmp_path / "mutated.sig"
    rng = random.Random(42)

    for _ in range(120):
        data = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            index = rng.randrange(len(data))
            data[index] = rng.randrange(256)
        package_path.write_bytes(data)

        result = VerifyService.verify_file(
            document,
            package_path,
            keypair.public_key,
        )
        assert isinstance(result.reason, VerificationReason)


# ---------------------------------------------------------------------------
# Key-file hardening
# ---------------------------------------------------------------------------


def test_key_service_rejects_oversized_key_file(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b"{" + b" " * DEFAULT_MAX_JSON_BYTES + b"}")

    with pytest.raises(KeyFileError):
        KeyService.load_public(path)


def test_key_service_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = write_package_text(
        tmp_path / "duplicate.json",
        '{"format": "RSA-PUB/1", "format": "RSA-PUB/1"}',
    )

    with pytest.raises(KeyFileError):
        KeyService.load_public(path)


def test_key_service_rejects_non_finite_values(tmp_path: Path) -> None:
    path = write_package_text(
        tmp_path / "nan.json",
        '{"format": "RSA-PUB/1", "n": NaN, "e": 65537}',
    )

    with pytest.raises(KeyFileError):
        KeyService.load_public(path)


def test_key_service_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(KeyFileError):
        KeyService.load_public(path)
