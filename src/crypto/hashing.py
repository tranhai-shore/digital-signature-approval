"""SHA-256 hashing helpers with streaming support for large documents."""

from __future__ import annotations

import hashlib
import os
from typing import BinaryIO

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
SHA256_DIGEST_SIZE = 32


def sha256_bytes(data: bytes | bytearray | memoryview) -> bytes:
    """Return the SHA-256 digest of an in-memory byte string."""

    return hashlib.sha256(data).digest()


def sha256_stream(
    stream: BinaryIO,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Hash a binary stream without loading it fully into memory."""

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    hasher = hashlib.sha256()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
    return hasher.digest()


def sha256_file(
    path: str | os.PathLike[str],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Return the SHA-256 digest of a file, read in fixed-size chunks."""

    with open(path, "rb") as handle:
        return sha256_stream(handle, chunk_size=chunk_size)
