"""Unit tests for SHA-256 hashing, including streaming behaviour."""

from __future__ import annotations

import hashlib
import io

import pytest

from src.crypto.hashing import sha256_bytes, sha256_file, sha256_stream


EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_known_vectors() -> None:
    assert sha256_bytes(b"").hex() == EMPTY_SHA256
    assert sha256_bytes(b"abc").hex() == ABC_SHA256


@pytest.mark.parametrize("chunk_size", [1, 2, 3, 7, 64, 1024])
def test_stream_matches_one_shot_hash(chunk_size: int) -> None:
    payload = bytes(range(256)) * 17
    stream = io.BytesIO(payload)
    assert sha256_stream(stream, chunk_size=chunk_size) == hashlib.sha256(
        payload
    ).digest()


def test_file_hash_matches_bytes_hash(tmp_path) -> None:
    payload = b"hop dong phe duyet " * 5000
    path = tmp_path / "contract.txt"
    path.write_bytes(payload)

    assert sha256_file(path, chunk_size=13) == sha256_bytes(payload)
    assert sha256_file(str(path)) == hashlib.sha256(payload).digest()


def test_invalid_chunk_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        sha256_stream(io.BytesIO(b"abc"), chunk_size=0)


def test_large_file_is_hashed_correctly(tmp_path) -> None:
    payload = (b"approval-block-" * 100_000) + b"END"
    path = tmp_path / "large.bin"
    path.write_bytes(payload)

    assert sha256_file(path, chunk_size=4096) == sha256_bytes(payload)
