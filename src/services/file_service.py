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
