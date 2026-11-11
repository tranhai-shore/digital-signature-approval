"""Atomic file helpers used for keys and signature packages."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_bytes(
    path: str | os.PathLike[str],
    data: bytes,
    *,
    mode: int | None = None,
) -> Path:
    """Write ``data`` to ``path`` atomically (temp file + ``os.replace``)."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    mode: int | None = None,
    encoding: str = "utf-8",
) -> Path:
    """Write text atomically using UTF-8 by default."""

    return atomic_write_bytes(path, text.encode(encoding), mode=mode)


def default_signature_path(document_path: str | os.PathLike[str]) -> Path:
    """Return ``<document>.sig`` next to the document."""

    document = Path(document_path)
    return document.with_name(document.name + ".sig")


def flip_bit(
    source: str | os.PathLike[str],
    output: str | os.PathLike[str],
    *,
    offset: int = 0,
    bit: int = 0,
) -> Path:
    """Copy ``source`` to ``output`` with one bit flipped.

    The source file is never modified.  The output is written atomically with
    the source file's permission bits.
    """

    source_path = Path(source)
    output_path = Path(output)

    if source_path.resolve() == output_path.resolve():
        raise ValueError(
            "refusing to overwrite the input file; choose another output path"
        )

    data = bytearray(source_path.read_bytes())
    if not data:
        raise ValueError(f"file is empty: {source_path}")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("offset must be an integer")
    if not 0 <= offset < len(data):
        raise ValueError(f"offset must be between 0 and {len(data) - 1}")
    if isinstance(bit, bool) or not isinstance(bit, int) or not 0 <= bit <= 7:
        raise ValueError("bit must be between 0 and 7")

    data[offset] ^= 1 << bit
    mode = source_path.stat().st_mode & 0o777
    return atomic_write_bytes(output_path, bytes(data), mode=mode)

