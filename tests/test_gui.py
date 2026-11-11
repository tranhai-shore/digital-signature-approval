"""Tests for GUI helpers and the Tkinter application shell."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.gui.support import (
    default_tampered_path,
    format_size,
    parse_integer,
    shorten,
)
from src.models.signature_package import SignaturePackage
from src.models.verification import VerificationReason, VerificationResult
from src.services.key_service import KeyService
from src.services.sign_service import SignResult


def test_format_size() -> None:
    assert format_size(0) == "0 B"
    assert format_size(512) == "512 B"
    assert format_size(1024) == "1.0 KiB"
    assert format_size(2048) == "2.0 KiB"
    assert format_size(5 * 1024 * 1024) == "5.0 MiB"


def test_format_size_rejects_negative() -> None:
    with pytest.raises(ValueError):
        format_size(-1)


def test_default_tampered_path() -> None:
    assert default_tampered_path("docs/contract.pdf") == Path(
        "docs/contract-tampered.pdf"
    )


def test_parse_integer() -> None:
    assert parse_integer(" 12 ", label="offset", minimum=0, maximum=20) == 12
    with pytest.raises(ValueError, match="số nguyên"):
        parse_integer("abc", label="offset")
    with pytest.raises(ValueError, match="lớn hơn"):
        parse_integer("-1", label="offset", minimum=0)
    with pytest.raises(ValueError, match="nhỏ hơn"):
        parse_integer("9", label="bit", maximum=7)


def test_shorten() -> None:
    assert shorten("short") == "short"
    value = "a" * 100
    assert shorten(value) == "a" * 16 + "…" + "a" * 8


tk = pytest.importorskip("tkinter")


@pytest.fixture
def app():
    from src.gui.app import DSIGApp

    try:
        application = DSIGApp()
    except tk.TclError as exc:  # pragma: no cover - depends on the display
        pytest.skip(f"Tk display unavailable: {exc}")
    application.withdraw()
    application.update_idletasks()
    try:
        yield application
    finally:
        application.destroy()


def test_app_exposes_four_tabs(app) -> None:
    titles = [
        app.notebook.tab(index, "text").strip()
        for index in range(app.notebook.index("end"))
    ]
    assert titles == ["Khóa", "Ký tài liệu", "Xác thực", "Demo sửa đổi"]
    assert app.title() == "DSIG — Ký số tài liệu phê duyệt"


def test_app_key_context_populates_sign_and_verify(app, tmp_path: Path) -> None:
    app.apply_key_context(
        private_path=tmp_path / "alice_private.json",
        public_path=tmp_path / "alice_public.json",
        fingerprint="sha256:" + "a" * 64,
    )

    assert app.sign_tab.key_var.get() == str(tmp_path / "alice_private.json")
    assert app.verify_tab.key_var.get() == str(tmp_path / "alice_public.json")
    assert app.last_fingerprint == "sha256:" + "a" * 64


def test_key_tab_updates_application_context(app, tmp_path: Path) -> None:
    generated = KeyService.generate("alice", bits=1024, keys_dir=tmp_path / "keys")

    app.key_tab._on_generated(generated)

    assert app.key_tab.fingerprint_var.get() == generated.fingerprint
    assert app.sign_tab.key_var.get() == str(generated.private_path)
    assert app.verify_tab.key_var.get() == str(generated.public_path)
    assert app.last_private_path == generated.private_path
    assert app.last_public_path == generated.public_path


def test_verify_tab_renders_failure(app) -> None:
    result = VerificationResult.failure(VerificationReason.HASH_MISMATCH)

    app.verify_tab._apply_result(result)

    assert "KHÔNG HỢP LỆ" in app.verify_tab.banner.cget("text")
    assert app.verify_tab.reason_var.get() == "HASH_MISMATCH"


def test_verify_tab_renders_success(app) -> None:
    package = SignaturePackage(
        signer="Alice",
        key_fingerprint="sha256:" + "b" * 64,
        original_name="contract.pdf",
        size=12,
        signed_at="2026-11-11T10:00:00Z",
        file_digest=bytes(range(32)),
        signature=b"\x01" * 128,
    )

    app.verify_tab._apply_result(VerificationResult.success(package))

    assert "HỢP LỆ" in app.verify_tab.banner.cget("text")
    assert app.verify_tab.reason_var.get() == "VALID"
    assert app.verify_tab.signer_var.get() == "Alice"
    assert app.verify_tab.fingerprint_var.get() == package.key_fingerprint


def test_demo_tab_builds_tampered_path(app, tmp_path: Path) -> None:
    document = tmp_path / "contract.pdf"

    app.demo_tab.set_context(document, tmp_path / "contract.pdf.sig")

    assert app.demo_tab.source_var.get() == str(document)
    assert app.demo_tab.output_var.get() == str(
        tmp_path / "contract-tampered.pdf"
    )


def test_sign_completion_populates_verify_and_demo_tabs(app, tmp_path: Path) -> None:
    document = tmp_path / "contract.pdf"
    document.write_bytes(b"contract data")
    package_path = tmp_path / "contract.pdf.sig"
    package = SignaturePackage(
        signer="Alice",
        key_fingerprint="sha256:" + "c" * 64,
        original_name="contract.pdf",
        size=13,
        signed_at="2026-11-11T10:00:00Z",
        file_digest=bytes(range(32)),
        signature=b"\x02" * 128,
    )
    app.sign_tab.document_var.set(str(document))

    app.sign_tab._on_signed(SignResult(package=package, package_path=package_path))

    assert app.demo_tab.source_var.get() == str(document)
    assert app.demo_tab.package_var.get() == str(package_path)
    assert app.verify_tab.document_var.get() == str(document)
    assert app.verify_tab.package_var.get() == str(package_path)
