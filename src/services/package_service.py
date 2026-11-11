"""Read and write ``.sig`` packages as UTF-8 JSON files."""

from __future__ import annotations

import os

from src.models.json_support import JSONSupportError, read_json_file
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
    Oversized, duplicate-keyed or non-finite JSON is rejected as
    :class:`PackageError`.
    """

    try:
        data = read_json_file(path)
    except JSONSupportError as exc:
        raise PackageError(f"package JSON rejected: {exc}") from exc

    if not isinstance(data, dict):
        raise PackageError("package must be a JSON object")
    return SignaturePackage.from_dict(data)
