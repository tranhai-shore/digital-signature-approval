"""Sign a document and produce a ``.sig`` package."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from src.crypto.hashing import sha256_bytes, sha256_file
from src.crypto.rsa import RSAPrivateKey
from src.crypto.signature import sign_bytes
from src.models.signature_package import (
    SIGNATURE_ALGORITHM,
    SignaturePackage,
    normalize_original_name,
)
from src.models.timestamp import canonicalize_timestamp, utc_now_iso
from src.services.file_service import default_signature_path
from src.services.package_service import write_package
from src.services.tbs import build_tbs


@dataclass(frozen=True, slots=True)
class SignResult:
    package: SignaturePackage
    package_path: Path


class SignService:
    """Build and persist signature packages for documents."""

    @staticmethod
    def _build_package(
        private_key: RSAPrivateKey,
        *,
        signer: str,
        original_name: str,
        size: int,
        file_digest: bytes,
        signed_at: str | None,
    ) -> SignaturePackage:
        if not isinstance(private_key, RSAPrivateKey):
            raise TypeError("private_key must be an RSAPrivateKey")

        timestamp = utc_now_iso() if signed_at is None else canonicalize_timestamp(signed_at)
        tbs = build_tbs(
            algorithm=SIGNATURE_ALGORITHM,
            signer=signer,
            original_name=original_name,
            size=size,
            signed_at=timestamp,
            file_digest=file_digest,
        )
        signature = sign_bytes(private_key, tbs)

        return SignaturePackage(
            signer=signer,
            key_fingerprint=private_key.public_key.fingerprint,
            original_name=original_name,
            size=size,
            signed_at=timestamp,
            file_digest=file_digest,
            signature=signature,
        )

    @staticmethod
    def build_package(
        private_key: RSAPrivateKey,
        document_path: str | os.PathLike[str],
        signer: str,
        *,
        signed_at: str | None = None,
    ) -> SignaturePackage:
        """Create a package for a file without writing it to disk."""

        path = Path(document_path)
        if not path.is_file():
            raise FileNotFoundError(f"document not found: {path}")

        return SignService._build_package(
            private_key,
            signer=signer,
            original_name=path.name,
            size=path.stat().st_size,
            file_digest=sha256_file(path),
            signed_at=signed_at,
        )

    @staticmethod
    def sign_data(
        private_key: RSAPrivateKey,
        data: bytes,
        signer: str,
        original_name: str,
        *,
        signed_at: str | None = None,
    ) -> SignaturePackage:
        """Create a package for in-memory bytes (useful for tests and GUIs)."""

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        return SignService._build_package(
            private_key,
            signer=signer,
            original_name=normalize_original_name(original_name),
            size=len(data),
            file_digest=sha256_bytes(data),
            signed_at=signed_at,
        )

    @staticmethod
    def sign_file(
        private_key: RSAPrivateKey,
        document_path: str | os.PathLike[str],
        signer: str,
        *,
        output_path: str | os.PathLike[str] | None = None,
        signed_at: str | None = None,
    ) -> SignResult:
        """Sign a file, write ``<document>.sig`` by default, and return both."""

        package = SignService.build_package(
            private_key,
            document_path,
            signer,
            signed_at=signed_at,
        )
        target = (
            Path(output_path)
            if output_path is not None
            else default_signature_path(document_path)
        )
        write_package(package, target)
        return SignResult(package=package, package_path=target)
