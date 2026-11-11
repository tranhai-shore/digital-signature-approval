"""Read and write ``.sig`` packages as UTF-8 JSON files."""

from __future__ import annotations

import os
from pathlib import Path

from src.models.signature_package import PackageError, SignaturePackage
from src.services.file_service import atomic_write_text


def write_package(
    package: SignaturePackage,
    path: str | os.PathLike[str],
) -> Path:
    """Serialize a package and write it atomically."""

    if not isinstance(package, SignaturePackage):
        raise TypeError("package must be a SignaturePackage")
    return atomic_write_text(path, package.to_json() + "\n", mode=0o644)


def read_package(path: str | os.PathLike[str]) -> SignaturePackage:
    """Read and validate a package file.

    ``FileNotFoundError`` and other ``OSError`` values are allowed to propagate
    so the verification service can distinguish "missing" from "malformed".
    """

    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PackageError("package is not valid UTF-8") from exc

    try:
        return SignaturePackage.from_json(text)
    except PackageError:
        raise
    except (TypeError, ValueError) as exc:
        raise PackageError("package contains invalid values") from exc
