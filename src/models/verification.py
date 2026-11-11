"""Verification result and machine-readable reason codes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from src.models.signature_package import SignaturePackage


class VerificationReason(str, Enum):
    """Stable reason codes used by the CLI, GUI and tests."""

    VALID = "VALID"
    PACKAGE_NOT_FOUND = "PACKAGE_NOT_FOUND"
    PACKAGE_MALFORMED = "PACKAGE_MALFORMED"
    PACKAGE_READ_ERROR = "PACKAGE_READ_ERROR"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"
    KEY_MISMATCH = "KEY_MISMATCH"
    SIGNER_MISMATCH = "SIGNER_MISMATCH"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    FILE_READ_ERROR = "FILE_READ_ERROR"
    SIZE_MISMATCH = "SIZE_MISMATCH"
    HASH_MISMATCH = "HASH_MISMATCH"
    SIGNATURE_MALFORMED = "SIGNATURE_MALFORMED"
    PADDING_INVALID = "PADDING_INVALID"
    TBS_MISMATCH = "TBS_MISMATCH"


MESSAGES: dict[VerificationReason, str] = {
    VerificationReason.VALID: (
        "Chữ ký hợp lệ. Tài liệu xác thực và chưa bị thay đổi."
    ),
    VerificationReason.PACKAGE_NOT_FOUND: "Không tìm thấy tệp chữ ký .sig.",
    VerificationReason.PACKAGE_MALFORMED: (
        "Tệp chữ ký không đúng định dạng hoặc đã bị hỏng."
    ),
    VerificationReason.PACKAGE_READ_ERROR: "Không đọc được tệp chữ ký .sig.",
    VerificationReason.UNSUPPORTED_ALGORITHM: (
        "Thuật toán chữ ký trong tệp không được hỗ trợ."
    ),
    VerificationReason.KEY_MISMATCH: (
        "Khóa công khai không khớp với fingerprint trong tệp chữ ký."
    ),
    VerificationReason.SIGNER_MISMATCH: (
        "Người ký trong tệp chữ ký không đúng với người ký mong đợi."
    ),
    VerificationReason.FILE_NOT_FOUND: "Không tìm thấy tài liệu cần xác thực.",
    VerificationReason.FILE_READ_ERROR: "Không đọc được tài liệu cần xác thực.",
    VerificationReason.SIZE_MISMATCH: (
        "Kích thước tài liệu không khớp với thông tin trong tệp chữ ký."
    ),
    VerificationReason.HASH_MISMATCH: (
        "Nội dung tài liệu đã bị thay đổi: SHA-256 không khớp."
    ),
    VerificationReason.SIGNATURE_MALFORMED: (
        "Chữ ký sai định dạng hoặc không hợp lệ với khóa công khai."
    ),
    VerificationReason.PADDING_INVALID: (
        "Cấu trúc padding PKCS#1 v1.5 của chữ ký không hợp lệ."
    ),
    VerificationReason.TBS_MISMATCH: (
        "Chữ ký không khớp với metadata (TBS) của tài liệu."
    ),
}


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of checking one document against one package."""

    valid: bool
    reason: VerificationReason
    message: str
    signer: str | None = None
    original_name: str | None = None
    signed_at: str | None = None
    key_fingerprint: str | None = None

    def __bool__(self) -> bool:
        return self.valid

    @classmethod
    def success(cls, package: SignaturePackage) -> "VerificationResult":
        return cls(
            valid=True,
            reason=VerificationReason.VALID,
            message=MESSAGES[VerificationReason.VALID],
            signer=package.signer,
            original_name=package.original_name,
            signed_at=package.signed_at,
            key_fingerprint=package.key_fingerprint,
        )

    @classmethod
    def failure(
        cls,
        reason: VerificationReason,
        package: SignaturePackage | None = None,
    ) -> "VerificationResult":
        return cls(
            valid=False,
            reason=reason,
            message=MESSAGES[reason],
            signer=package.signer if package else None,
            original_name=package.original_name if package else None,
            signed_at=package.signed_at if package else None,
            key_fingerprint=package.key_fingerprint if package else None,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason.value,
            "message": self.message,
            "signer": self.signer,
            "original_name": self.original_name,
            "signed_at": self.signed_at,
            "key_fingerprint": self.key_fingerprint,
        }
