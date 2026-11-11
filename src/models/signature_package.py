"""Signature package model (``.sig`` file) and metadata validation."""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass

from src.crypto.encoding import b64url_decode, b64url_encode
from src.models.json_support import JSONSupportError, loads_strict
from src.models.timestamp import canonicalize_timestamp

PACKAGE_FORMAT = "DSIG/1"
SIGNATURE_ALGORITHM = "RSA-PKCS1v15-SHA256"
SHA256_HEX_LENGTH = 64
MAX_SIGNER_CHARACTERS = 256
MAX_ORIGINAL_NAME_CHARACTERS = 255

_FINGERPRINT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")


class PackageError(ValueError):
    """Raised when a ``.sig`` package is malformed or unsupported."""


class UnsupportedAlgorithmError(PackageError):
    """Raised when a package declares an unknown signature algorithm."""


def _has_control_characters(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _require_valid_unicode(value: str, label: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PackageError(f"{label} must be valid Unicode text") from exc
    return value


def normalize_signer(value: str) -> str:
    """Normalize a signer identifier (Unicode NFC, trimmed, no controls)."""

    if not isinstance(value, str):
        raise PackageError("signer must be a string")
    normalized = _require_valid_unicode(
        unicodedata.normalize("NFC", value).strip(),
        "signer",
    )
    if not normalized:
        raise PackageError("signer must not be empty")
    if _has_control_characters(normalized):
        raise PackageError("signer must not contain control characters")
    if len(normalized) > MAX_SIGNER_CHARACTERS:
        raise PackageError(
            f"signer must be at most {MAX_SIGNER_CHARACTERS} characters"
        )
    return normalized


def normalize_original_name(value: str) -> str:
    """Normalize a document filename and reject path traversal components."""

    if not isinstance(value, str):
        raise PackageError("original_name must be a string")
    normalized = _require_valid_unicode(
        unicodedata.normalize("NFC", value),
        "original_name",
    )
    if not normalized or normalized in {".", ".."}:
        raise PackageError("original_name must not be empty or a dot component")
    if "/" in normalized or "\\" in normalized:
        raise PackageError("original_name must be a basename, not a path")
    if _has_control_characters(normalized):
        raise PackageError("original_name must not contain control characters")
    if len(normalized) > MAX_ORIGINAL_NAME_CHARACTERS:
        raise PackageError(
            "original_name must be at most "
            f"{MAX_ORIGINAL_NAME_CHARACTERS} characters"
        )
    return normalized


def validate_fingerprint(value: str) -> str:
    """Validate a public-key fingerprint in ``sha256:<64 lowercase hex>`` form."""

    if not isinstance(value, str) or not _FINGERPRINT_RE.fullmatch(value):
        raise PackageError("key_fingerprint must look like 'sha256:<64 hex>'")
    return value


def _validate_size(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PackageError("file size must be an integer")
    if value < 0 or value >= 2**64:
        raise PackageError("file size must be between 0 and 2^64 - 1")
    return value


def _validate_digest(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise PackageError("file digest must be exactly 32 bytes (SHA-256)")
    return value


def _require_string(mapping: dict[str, object], key: str, label: str) -> str:
    value = mapping[key]
    if not isinstance(value, str):
        raise PackageError(f"{label} must be a string")
    return value


@dataclass(frozen=True, slots=True)
class SignaturePackage:
    """Signed metadata and signature for one document.

    The signature itself is computed over the TBS built from these metadata
    fields, not over the JSON text.  Re-serializing the package therefore does
    not invalidate an otherwise untouched signature.
    """

    signer: str
    key_fingerprint: str
    original_name: str
    size: int
    signed_at: str
    file_digest: bytes
    signature: bytes
    algorithm: str = SIGNATURE_ALGORITHM
    format: str = PACKAGE_FORMAT

    def __post_init__(self) -> None:
        if self.format != PACKAGE_FORMAT:
            raise PackageError(f"unsupported package format: {self.format!r}")
        if self.algorithm != SIGNATURE_ALGORITHM:
            raise UnsupportedAlgorithmError(
                f"unsupported signature algorithm: {self.algorithm!r}"
            )

        object.__setattr__(self, "signer", normalize_signer(self.signer))
        object.__setattr__(
            self, "original_name", normalize_original_name(self.original_name)
        )
        object.__setattr__(
            self,
            "key_fingerprint",
            validate_fingerprint(self.key_fingerprint),
        )
        object.__setattr__(self, "size", _validate_size(self.size))
        if not isinstance(self.signed_at, str):
            raise PackageError("signed_at must be a string")
        try:
            timestamp = canonicalize_timestamp(self.signed_at)
        except ValueError as exc:
            raise PackageError("signed_at is not a valid ISO-8601 timestamp") from exc
        object.__setattr__(self, "signed_at", timestamp)
        object.__setattr__(self, "file_digest", _validate_digest(self.file_digest))

        if not isinstance(self.signature, bytes) or not self.signature:
            raise PackageError("signature must be a non-empty bytes value")

    @property
    def file_sha256(self) -> str:
        """Hex representation of the signed document digest."""

        return self.file_digest.hex()

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "algorithm": self.algorithm,
            "signer": self.signer,
            "key_fingerprint": self.key_fingerprint,
            "file": {
                "original_name": self.original_name,
                "size": self.size,
                "sha256": self.file_sha256,
            },
            "signed_at": self.signed_at,
            "signature": b64url_encode(self.signature),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "SignaturePackage":
        if not isinstance(data, dict):
            raise PackageError("package must be a JSON object")

        try:
            file_data = data["file"]
            if not isinstance(file_data, dict):
                raise PackageError("'file' must be a JSON object")

            sha256_hex = file_data["sha256"]
            if not isinstance(sha256_hex, str) or not _SHA256_HEX_RE.fullmatch(
                sha256_hex
            ):
                raise PackageError("file.sha256 must be 64 lowercase hex characters")

            signature_text = data["signature"]
            if not isinstance(signature_text, str):
                raise PackageError("signature must be a base64url string")
            try:
                signature = b64url_decode(signature_text)
            except ValueError as exc:
                raise PackageError("signature is not valid base64url") from exc

            size_value = file_data["size"]
            if isinstance(size_value, bool) or not isinstance(size_value, int):
                raise PackageError("file.size must be an integer")

            return cls(
                format=_require_string(data, "format", "format"),
                algorithm=_require_string(data, "algorithm", "algorithm"),
                signer=_require_string(data, "signer", "signer"),
                key_fingerprint=_require_string(
                    data, "key_fingerprint", "key_fingerprint"
                ),
                original_name=_require_string(
                    file_data, "original_name", "file.original_name"
                ),
                size=size_value,
                signed_at=_require_string(data, "signed_at", "signed_at"),
                file_digest=bytes.fromhex(sha256_hex),
                signature=signature,
            )
        except KeyError as exc:
            raise PackageError(f"missing package field: {exc.args[0]}") from exc
        except (TypeError, ValueError) as exc:
            if isinstance(exc, PackageError):
                raise
            raise PackageError("package contains invalid values") from exc

    @classmethod
    def from_json(cls, text: str) -> "SignaturePackage":
        if not isinstance(text, str):
            raise PackageError("package JSON must be text")
        try:
            data = loads_strict(text)
        except JSONSupportError as exc:
            raise PackageError(f"package JSON rejected: {exc}") from exc
        if not isinstance(data, dict):
            raise PackageError("package must be a JSON object")
        return cls.from_dict(data)
