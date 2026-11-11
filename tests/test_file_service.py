"""Tests for atomic writes, signature paths and the tamper helper."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.file_service import (
    atomic_write_bytes,
    atomic_write_text,
    default_signature_path,
    flip_bit,
)


def test_atomic_write_bytes_and_text(tmp_path: Path) -> None:
    binary = atomic_write_bytes(tmp_path / "data.bin", b"\x00\x01")
    text = atomic_write_text(tmp_path / "notes.txt", "nội dung")

    assert binary.read_bytes() == b"\x00\x01"
    assert text.read_text(encoding="utf-8") == "nội dung"
    assert list(tmp_path.glob("*.tmp")) == []


def test_default_signature_path(tmp_path: Path) -> None:
    document = tmp_path / "contract.pdf"
    assert default_signature_path(document) == tmp_path / "contract.pdf.sig"


def test_flip_bit_changes_exactly_one_bit(tmp_path: Path) -> None:
    source = tmp_path / "contract.txt"
    original = bytes(range(64))
    source.write_bytes(original)

    output = flip_bit(source, tmp_path / "tampered.txt", offset=5, bit=3)

    assert source.read_bytes() == original
    modified = output.read_bytes()
    assert len(modified) == len(original)
    differences = [
        index
        for index, (left, right) in enumerate(zip(original, modified))
        if left != right
    ]
    assert differences == [5]
    assert modified[5] == original[5] ^ (1 << 3)


def test_flip_bit_rejects_overwriting_source(tmp_path: Path) -> None:
    source = tmp_path / "contract.txt"
    source.write_bytes(b"data")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        flip_bit(source, source)


@pytest.mark.parametrize(
    ("offset", "bit", "message"),
    [
        (0, 8, "bit"),
        (0, -1, "bit"),
        (4, 0, "offset"),
        (99, 0, "offset"),
    ],
)
def test_flip_bit_rejects_invalid_positions(
    tmp_path: Path,
    offset: int,
    bit: int,
    message: str,
) -> None:
    source = tmp_path / "contract.txt"
    source.write_bytes(b"data")

    with pytest.raises(ValueError, match=message):
        flip_bit(source, tmp_path / "out.txt", offset=offset, bit=bit)


def test_flip_bit_rejects_empty_file(tmp_path: Path) -> None:
    source = tmp_path / "empty.txt"
    source.write_bytes(b"")

    with pytest.raises(ValueError, match="empty"):
        flip_bit(source, tmp_path / "out.txt")
