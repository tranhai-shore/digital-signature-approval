"""Verify a document against a ``.sig`` package and classify failures."""

from __future__ import annotations

import os
from pathlib import Path

from src.crypto.encoding import constant_time_compare
from src.crypto.hashing import sha256_bytes, sha256_file
from src.crypto.padding import PaddingError
from src.crypto.rsa import RSAPublicKey
from src.crypto.signature import SignatureFormatError, recover_digest
from src.models.signature_package import (
    PackageError,
    SignaturePackage,
    UnsupportedAlgorithmError,
    normalize_signer,
)
from src.models.verification import VerificationReason, VerificationResult
from src.services.package_service import read_package
from src.services.tbs import build_tbs


class VerifyService:
    """Verify signatures while returning stable, user-presentable reason codes."""

    @staticmethod
    def _coerce_package(
        package: SignaturePackage | str | os.PathLike[str],
    ) -> tuple[SignaturePackage | None, VerificationResult | None]:
        if isinstance(package, SignaturePackage):
            return package, None

        try:
            return read_package(package), None
        except FileNotFoundError:
            return None, VerificationResult.failure(
                VerificationReason.PACKAGE_NOT_FOUND
            )
        except OSError:
            return None, VerificationResult.failure(
                VerificationReason.PACKAGE_READ_ERROR
            )
        except UnsupportedAlgorithmError:
            return None, VerificationResult.failure(
                VerificationReason.UNSUPPORTED_ALGORITHM
            )
        except PackageError:
            return None, VerificationResult.failure(
                VerificationReason.PACKAGE_MALFORMED
            )

    @staticmethod
    def _check_identity(
        package: SignaturePackage,
        public_key: RSAPublicKey,
        expected_signer: str | None,
    ) -> VerificationResult | None:
        if not isinstance(public_key, RSAPublicKey):
            raise TypeError("public_key must be an RSAPublicKey")

        if expected_signer is not None:
            try:
                expected = normalize_signer(expected_signer)
            except PackageError as exc:
                raise ValueError("expected_signer is invalid") from exc
            if package.signer != expected:
                return VerificationResult.failure(
                    VerificationReason.SIGNER_MISMATCH,
                    package,
                )

        if not constant_time_compare(
            public_key.fingerprint.encode("ascii"),
            package.key_fingerprint.encode("ascii"),
        ):
            return VerificationResult.failure(
                VerificationReason.KEY_MISMATCH,
                package,
            )
        return None

    @staticmethod
    def _verify_digest(
        package: SignaturePackage,
        public_key: RSAPublicKey,
        actual_digest: bytes,
    ) -> VerificationResult:
        if not constant_time_compare(actual_digest, package.file_digest):
            return VerificationResult.failure(
                VerificationReason.HASH_MISMATCH,
                package,
            )

        tbs = build_tbs(
            algorithm=package.algorithm,
            signer=package.signer,
            original_name=package.original_name,
            size=package.size,
            signed_at=package.signed_at,
            file_digest=package.file_digest,
        )
        expected_tbs_digest = sha256_bytes(tbs)

        try:
            recovered = recover_digest(public_key, package.signature)
        except SignatureFormatError:
            return VerificationResult.failure(
                VerificationReason.SIGNATURE_MALFORMED,
                package,
            )
        except PaddingError:
            return VerificationResult.failure(
                VerificationReason.PADDING_INVALID,
                package,
            )
        except ValueError:
            return VerificationResult.failure(
                VerificationReason.SIGNATURE_MALFORMED,
                package,
            )

        if not constant_time_compare(recovered, expected_tbs_digest):
            return VerificationResult.failure(
                VerificationReason.TBS_MISMATCH,
                package,
            )

        return VerificationResult.success(package)

    @staticmethod
    def verify_file(
        document_path: str | os.PathLike[str],
        package: SignaturePackage | str | os.PathLike[str],
        public_key: RSAPublicKey,
        *,
        expected_signer: str | None = None,
    ) -> VerificationResult:
        """Verify a file on disk, hashing it in chunks."""

        parsed, failure = VerifyService._coerce_package(package)
        if failure is not None:
            return failure
        assert parsed is not None

        failure = VerifyService._check_identity(parsed, public_key, expected_signer)
        if failure is not None:
            return failure

        path = Path(document_path)
        try:
            stat = path.stat()
        except FileNotFoundError:
            return VerificationResult.failure(VerificationReason.FILE_NOT_FOUND, parsed)
        except OSError:
            return VerificationResult.failure(VerificationReason.FILE_READ_ERROR, parsed)

        if not path.is_file():
            return VerificationResult.failure(VerificationReason.FILE_NOT_FOUND, parsed)
        if stat.st_size != parsed.size:
            return VerificationResult.failure(
                VerificationReason.SIZE_MISMATCH,
                parsed,
            )

        try:
            digest = sha256_file(path)
        except OSError:
            return VerificationResult.failure(VerificationReason.FILE_READ_ERROR, parsed)

        return VerifyService._verify_digest(parsed, public_key, digest)

    @staticmethod
    def verify_data(
        data: bytes,
        package: SignaturePackage | str | os.PathLike[str],
        public_key: RSAPublicKey,
        *,
        expected_signer: str | None = None,
    ) -> VerificationResult:
        """Verify in-memory bytes against a package."""

        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")

        parsed, failure = VerifyService._coerce_package(package)
        if failure is not None:
            return failure
        assert parsed is not None

        failure = VerifyService._check_identity(parsed, public_key, expected_signer)
        if failure is not None:
            return failure

        if len(data) != parsed.size:
            return VerificationResult.failure(
                VerificationReason.SIZE_MISMATCH,
                parsed,
            )

        return VerifyService._verify_digest(parsed, public_key, sha256_bytes(data))
