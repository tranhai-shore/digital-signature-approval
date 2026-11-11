"""Tests for the canonical TBS construction."""

from __future__ import annotations

import unicodedata

import pytest

from src.models.signature_package import SIGNATURE_ALGORITHM
from src.services.tbs import TBS_DOMAIN, build_tbs

DIGEST = bytes(range(32))
BASE = {
    "algorithm": SIGNATURE_ALGORITHM,
    "signer": "alice",
    "original_name": "contract.pdf",
    "size": 1234,
    "signed_at": "2026-11-11T10:00:00Z",
    "file_digest": DIGEST,
}


def tbs(**overrides: object) -> bytes:
    values = {**BASE, **overrides}
    return build_tbs(**values)  # type: ignore[arg-type]


def test_domain_separator_and_determinism() -> None:
    first = tbs()
    assert first.startswith(TBS_DOMAIN)
    assert first == tbs()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signer", "bob"),
        ("original_name", "contract-final.pdf"),
        ("size", 1235),
        ("signed_at", "2026-11-11T10:00:01Z"),
        ("file_digest", bytes(reversed(DIGEST))),
    ],
)
def test_each_metadata_field_changes_tbs(field: str, value: object) -> None:
    assert tbs(**{field: value}) != tbs()


def test_length_prefixes_prevent_field_ambiguity() -> None:
    left = tbs(signer="ab", original_name="c")
    right = tbs(signer="a", original_name="bc")
    assert left != right


def test_unicode_is_normalised_to_nfc() -> None:
    composed = "Nguyễn Văn A"
    decomposed = unicodedata.normalize("NFD", composed)
    assert tbs(signer=composed) == tbs(signer=decomposed)


def test_timestamp_is_normalised_to_utc() -> None:
    assert tbs(signed_at="2026-11-11T17:00:00+07:00") == tbs(
        signed_at="2026-11-11T10:00:00Z"
    )


def test_size_boundaries_are_encodable() -> None:
    assert tbs(size=0)
    assert tbs(size=2**64 - 1)


@pytest.mark.parametrize(
    "overrides",
    [
        {"algorithm": "RSA-SHA1"},
        {"signer": ""},
        {"signer": "alice\x00"},
        {"original_name": "../secret.pdf"},
        {"original_name": "folder/contract.pdf"},
        {"size": -1},
        {"size": 2**64},
        {"size": True},
        {"file_digest": b"\x00" * 31},
        {"file_digest": bytearray(32)},
        {"signed_at": "2026-11-11T10:00:00"},
        {"signed_at": "not-a-date"},
    ],
)
def test_invalid_metadata_is_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        tbs(**overrides)
