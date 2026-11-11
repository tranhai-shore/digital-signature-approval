"""Tkinter desktop application for document signing and verification."""

from __future__ import annotations

import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Sequence

import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, ttk

from src import __version__
from src.crypto.hashing import sha256_file
from src.crypto.rsa import RSAPrivateKey, RSAPublicKey
from src.models.signature_package import SignaturePackage
from src.models.verification import VerificationResult
from src.services.file_service import default_signature_path, flip_bit
from src.services.key_service import GeneratedKey, KeyService, validate_key_name
from src.services.sign_service import SignResult, SignService
from src.services.verify_service import VerifyService

from src.gui.support import default_tampered_path, format_size, parse_integer

_JSON_FILTER = [("JSON key files", "*.json"), ("All files", "*.*")]
_PACKAGE_FILTER = [("Signature packages", "*.sig"), ("All files", "*.*")]
_DOCUMENT_FILTER = [
    ("Documents", "*.pdf *.txt *.doc *.docx *.odt"),
    ("PDF", "*.pdf"),
    ("Text", "*.txt"),
    ("All files", "*.*"),
]


def _is_file(text: str) -> bool:
    text = text.strip()
    if not text:
        return False
    try:
        return Path(text).is_file()
    except OSError:
        return False


class BaseTab(ttk.Frame):
    """Shared layout and file-dialog helpers for tabs."""

    def __init__(self, app: "DSIGApp") -> None:
        super().__init__(app, padding=14)
        self.app = app

    @staticmethod
    def set_enabled(widget: ttk.Widget, enabled: bool) -> None:
        widget.state(["!disabled"] if enabled else ["disabled"])

    def ask_open(self, title: str, filetypes: Sequence[tuple[str, str]]) -> Path | None:
        filename = filedialog.askopenfilename(
            parent=self.app,
            title=title,
            filetypes=filetypes,
        )
        return Path(filename) if filename else None

    def ask_save(
        self,
        title: str,
        default_name: str,
        filetypes: Sequence[tuple[str, str]],
    ) -> Path | None:
        filename = filedialog.asksaveasfilename(
            parent=self.app,
            title=title,
            initialfile=default_name,
            defaultextension=Path(default_name).suffix,
            filetypes=filetypes,
        )
        return Path(filename) if filename else None


class KeyTab(BaseTab):
    """Generate, load and export RSA key pairs."""

    def __init__(self, app: "DSIGApp") -> None:
        super().__init__(app)
        self._private_key: RSAPrivateKey | None = None
        self._public_key: RSAPublicKey | None = None
        self._private_path: Path | None = None
        self._public_path: Path | None = None

        self.name_var = tk.StringVar(value="alice")
        self.bits_var = tk.StringVar(value="2048")
        self.dir_var = tk.StringVar(value="keys")
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.fingerprint_var = tk.StringVar(value="—")
        self.private_var = tk.StringVar(value="—")
        self.public_var = tk.StringVar(value="—")

        self._build()
        self._update_actions()

    def _build(self) -> None:
        generate = ttk.LabelFrame(self, text="Tạo cặp khóa", padding=12)
        generate.pack(fill="x")
        generate.columnconfigure(1, weight=1)

        ttk.Label(generate, text="Tên khóa").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(generate, textvariable=self.name_var, width=28).grid(
            row=0, column=1, sticky="ew", padx=(8, 16), pady=4
        )
        ttk.Label(generate, text="Độ dài (bit)").grid(
            row=0, column=2, sticky="w", pady=4
        )
        bits = ttk.Combobox(
            generate,
            textvariable=self.bits_var,
            values=("1024", "2048", "3072", "4096"),
            state="readonly",
            width=8,
        )
        bits.grid(row=0, column=3, sticky="w", padx=(8, 0), pady=4)

        ttk.Label(generate, text="Thư mục lưu khóa").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(generate, textvariable=self.dir_var).grid(
            row=1, column=1, columnspan=2, sticky="ew", padx=(8, 16), pady=4
        )
        ttk.Button(
            generate,
            text="Duyệt…",
            command=self._browse_directory,
        ).grid(row=1, column=3, sticky="w", pady=4)

        ttk.Label(generate, text="Mật khẩu bảo vệ").grid(
            row=2, column=0, sticky="w", pady=4
        )
        self.password_entry = ttk.Entry(
            generate,
            textvariable=self.password_var,
            show="*",
        )
        self.password_entry.grid(
            row=2, column=1, sticky="ew", padx=(8, 16), pady=4
        )
        ttk.Checkbutton(
            generate,
            text="Hiện",
            variable=self.show_password_var,
            command=self._toggle_password,
        ).grid(row=2, column=2, sticky="w", pady=4)
        ttk.Label(
            generate,
            text="Để trống nếu không mã hóa khóa riêng.",
            style="Muted.TLabel",
        ).grid(row=2, column=3, sticky="w", pady=4)

        actions = ttk.Frame(generate)
        actions.grid(row=3, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.generate_button = ttk.Button(
            actions,
            text="Tạo khóa",
            command=self._generate,
        )
        self.generate_button.pack(side="left")
        self.load_public_button = ttk.Button(
            actions,
            text="Nạp khóa công khai…",
            command=self._load_public,
        )
        self.load_public_button.pack(side="left", padx=(8, 0))
        self.load_private_button = ttk.Button(
            actions,
            text="Nạp khóa riêng…",
            command=self._load_private,
        )
        self.load_private_button.pack(side="left", padx=(8, 0))

        info = ttk.LabelFrame(self, text="Thông tin khóa", padding=12)
        info.pack(fill="both", expand=True, pady=(12, 0))
        info.columnconfigure(1, weight=1)

        ttk.Label(info, text="Fingerprint").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            info,
            textvariable=self.fingerprint_var,
            state="readonly",
        ).grid(row=0, column=1, sticky="ew", padx=(8, 8), pady=4)
        self.copy_button = ttk.Button(
            info,
            text="Sao chép",
            command=self._copy_fingerprint,
        )
        self.copy_button.grid(row=0, column=2, sticky="w", pady=4)

        ttk.Label(info, text="Khóa riêng").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            info,
            textvariable=self.private_var,
            state="readonly",
        ).grid(row=1, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=4)

        ttk.Label(info, text="Khóa công khai").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            info,
            textvariable=self.public_var,
            state="readonly",
        ).grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 0), pady=4)

        actions = ttk.Frame(info)
        actions.grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.use_sign_button = ttk.Button(
            actions,
            text="Dùng để ký",
            command=self._use_for_signing,
        )
        self.use_sign_button.pack(side="left")
        self.use_verify_button = ttk.Button(
            actions,
            text="Dùng để xác thực",
            command=self._use_for_verification,
        )
        self.use_verify_button.pack(side="left", padx=(8, 0))
        self.export_public_button = ttk.Button(
            actions,
            text="Xuất khóa công khai…",
            command=self._export_public,
        )
        self.export_public_button.pack(side="left", padx=(8, 0))
        self.export_private_button = ttk.Button(
            actions,
            text="Xuất khóa riêng…",
            command=self._export_private,
        )
        self.export_private_button.pack(side="left", padx=(8, 0))

    def _toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_password_var.get() else "*")

    def _browse_directory(self) -> None:
        directory = filedialog.askdirectory(
            parent=self.app,
            title="Chọn thư mục lưu khóa",
            initialdir=self.dir_var.get() or ".",
        )
        if directory:
            self.dir_var.set(directory)

    def _generate(self) -> None:
        try:
            name = validate_key_name(self.name_var.get())
        except ValueError as exc:
            messagebox.showerror("Tên khóa không hợp lệ", str(exc), parent=self.app)
            return

        try:
            bits = parse_integer(self.bits_var.get(), label="Độ dài khóa", minimum=1024)
        except ValueError as exc:
            messagebox.showerror("Độ dài khóa không hợp lệ", str(exc), parent=self.app)
            return

        directory = Path(self.dir_var.get().strip() or "keys")
        private_path = directory / f"{name}_private.json"
        public_path = directory / f"{name}_public.json"
        if private_path.exists() or public_path.exists():
            if not messagebox.askyesno(
                "Ghi đè khóa?",
                f"Khóa '{name}' đã tồn tại trong {directory}.\n"
                "Ghi đè sẽ làm mất khóa cũ. Tiếp tục?",
                parent=self.app,
            ):
                return

        password = self.password_var.get() or None
        started = self.app.run_task(
            f"Đang tạo khóa RSA-{bits}…",
            lambda: KeyService.generate(
                name,
                bits=bits,
                keys_dir=directory,
                password=password,
            ),
            self._on_generated,
            error_title="Không tạo được khóa",
            widgets=(
                self.generate_button,
                self.load_public_button,
                self.load_private_button,
            ),
        )
        if started:
            self.app.log(f"Bắt đầu tạo khóa '{name}' ({bits} bit).")

    def _on_generated(self, generated: GeneratedKey) -> None:
        self._private_key = generated.private_key
        self._private_path = generated.private_path
        self._public_key = generated.private_key.public_key
        self._public_path = generated.public_path
        self.fingerprint_var.set(generated.fingerprint)
        self.private_var.set(str(generated.private_path))
        self.public_var.set(str(generated.public_path))
        self._update_actions()
        self.app.apply_key_context(
            private_path=generated.private_path,
            public_path=generated.public_path,
            fingerprint=generated.fingerprint,
        )
        self.app.log(
            f"Đã tạo khóa '{generated.private_path.name}' — "
            f"{generated.fingerprint}"
        )
        self.app.set_status("Tạo khóa thành công.")

    def _load_public(self) -> None:
        path = self.ask_open("Chọn khóa công khai", _JSON_FILTER)
        if path is None:
            return
        self.app.run_task(
            "Đang nạp khóa công khai…",
            lambda: KeyService.load_public(path),
            lambda key: self._on_public_loaded(path, key),
            error_title="Không nạp được khóa công khai",
            widgets=(self.load_public_button,),
        )

    def _on_public_loaded(self, path: Path, key: RSAPublicKey) -> None:
        self._public_key = key
        self._public_path = path
        self.fingerprint_var.set(key.fingerprint)
        self.public_var.set(str(path))
        if (
            self._private_key is not None
            and self._private_key.public_key.fingerprint != key.fingerprint
        ):
            self.app.log(
                "Cảnh báo: khóa công khai vừa nạp không khớp khóa riêng hiện tại."
            )
        self._update_actions()
        self.app.apply_key_context(public_path=path, fingerprint=key.fingerprint)
        self.app.log(f"Đã nạp khóa công khai: {path}")
        self.app.set_status("Nạp khóa công khai thành công.")

    def _load_private(self) -> None:
        path = self.ask_open("Chọn khóa riêng", _JSON_FILTER)
        if path is None:
            return
        password = self.password_var.get() or None
        self.app.run_task(
            "Đang nạp khóa riêng…",
            lambda: KeyService.load_private(path, password=password),
            lambda key: self._on_private_loaded(path, key),
            error_title="Không nạp được khóa riêng",
            widgets=(self.load_private_button,),
        )

    def _on_private_loaded(self, path: Path, key: RSAPrivateKey) -> None:
        self._private_key = key
        self._private_path = path
        self._public_key = key.public_key
        self.fingerprint_var.set(key.public_key.fingerprint)
        self.private_var.set(str(path))

        sibling = path.with_name(path.name.replace("_private.json", "_public.json"))
        if sibling != path and sibling.is_file():
            self._public_path = sibling
            self.public_var.set(str(sibling))
        else:
            self._public_path = None
            self.public_var.set(
                "(chưa có tệp khóa công khai — hãy xuất khóa công khai)"
            )
            self.app.verify_tab.set_key_path("")

        self._update_actions()
        self.app.apply_key_context(
            private_path=path,
            public_path=self._public_path,
            fingerprint=key.public_key.fingerprint,
        )
        self.app.log(f"Đã nạp khóa riêng: {path}")
        self.app.set_status("Nạp khóa riêng thành công.")

    def _export_public(self) -> None:
        if self._public_key is None:
            return
        default_name = (
            self._public_path.name if self._public_path else "public_key.json"
        )
        target = self.ask_save("Xuất khóa công khai", default_name, _JSON_FILTER)
        if target is None:
            return
        self.app.run_task(
            "Đang xuất khóa công khai…",
            lambda: KeyService.save_public(self._public_key, target),
            lambda path: self._on_public_exported(path),
            error_title="Không xuất được khóa công khai",
            widgets=(self.export_public_button,),
        )

    def _on_public_exported(self, path: Path) -> None:
        self._public_path = path
        self.public_var.set(str(path))
        self._update_actions()
        self.app.apply_key_context(public_path=path)
        self.app.log(f"Đã xuất khóa công khai: {path}")
        self.app.set_status("Xuất khóa công khai thành công.")

    def _export_private(self) -> None:
        if self._private_key is None:
            return

        password = self.password_var.get() or None
        protection = (
            "Khóa xuất ra sẽ được mã hóa bằng mật khẩu hiện tại."
            if password is not None
            else "Khóa xuất ra sẽ KHÔNG được mã hóa vì ô mật khẩu đang trống."
        )
        if not messagebox.askyesno(
            "Cảnh báo bảo mật",
            "Tệp khóa riêng cho phép ký tài liệu thay mặt bạn.\n"
            "Chỉ xuất khi thật sự cần và bảo vệ tệp cẩn thận.\n\n"
            f"{protection}\n\n"
            "Tiếp tục xuất khóa riêng?",
            parent=self.app,
        ):
            return

        default_name = (
            self._private_path.name if self._private_path else "private_key.json"
        )
        target = self.ask_save("Xuất khóa riêng", default_name, _JSON_FILTER)
        if target is None:
            return

        self.app.run_task(
            "Đang xuất khóa riêng…",
            lambda: KeyService.save_private(
                self._private_key,
                target,
                password=password,
            ),
            lambda path: self._on_private_exported(path, password is not None),
            error_title="Không xuất được khóa riêng",
            widgets=(self.export_private_button,),
        )

    def _on_private_exported(self, path: Path, encrypted: bool) -> None:
        protection = "có mật khẩu" if encrypted else "KHÔNG mã hóa"
        self.app.log(f"Đã xuất khóa riêng ({protection}): {path}")
        self.app.set_status("Xuất khóa riêng thành công.")

    def _copy_fingerprint(self) -> None:
        fingerprint = self.fingerprint_var.get()
        if fingerprint and fingerprint != "—":
            self.clipboard_clear()
            self.clipboard_append(fingerprint)
            self.app.set_status("Đã sao chép fingerprint.")

    def _use_for_signing(self) -> None:
        if self._private_path is None:
            return
        self.app.sign_tab.set_key_path(self._private_path)
        self.app.notebook.select(self.app.sign_tab)
        self.app.set_status("Đã chọn khóa riêng cho tab ký.")

    def _use_for_verification(self) -> None:
        if self._public_path is None:
            return
        self.app.verify_tab.set_key_path(self._public_path)
        self.app.notebook.select(self.app.verify_tab)
        self.app.set_status("Đã chọn khóa công khai cho tab xác thực.")

    def _update_actions(self) -> None:
        has_private = self._private_key is not None
        has_public = self._public_key is not None
        has_fingerprint = self.fingerprint_var.get() not in ("", "—")
        self.set_enabled(self.copy_button, has_fingerprint)
        self.set_enabled(
            self.use_sign_button,
            has_private and self._private_path is not None,
        )
        self.set_enabled(
            self.use_verify_button,
            has_public and self._public_path is not None,
        )
        self.set_enabled(self.export_public_button, has_public)
        self.set_enabled(self.export_private_button, has_private)


class SignTab(BaseTab):
    """Choose a document, inspect its digest and create a signature package."""

    def __init__(self, app: "DSIGApp") -> None:
        super().__init__(app)
        self.package_path: Path | None = None

        self.key_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.document_var = tk.StringVar()
        self.signer_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.hash_var = tk.StringVar(value="—")
        self.size_var = tk.StringVar(value="—")
        self.package_var = tk.StringVar(value="—")
        self.fingerprint_var = tk.StringVar(value="—")
        self.signed_at_var = tk.StringVar(value="—")

        for variable in (self.key_var, self.document_var, self.signer_var):
            variable.trace_add("write", lambda *_: self._update_state())

        self._build()
        self._update_state()

    def _build(self) -> None:
        form = ttk.LabelFrame(self, text="Tài liệu và khóa", padding=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Khóa riêng").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.key_var).grid(
            row=0, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_key).grid(
            row=0, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Mật khẩu").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            form,
            textvariable=self.password_var,
            show="*",
        ).grid(row=1, column=1, sticky="ew", padx=(8, 8), pady=4)
        ttk.Label(
            form,
            text="Chỉ cần nếu khóa riêng được mã hóa.",
            style="Muted.TLabel",
        ).grid(row=1, column=2, sticky="w", pady=4)

        ttk.Label(form, text="Tài liệu").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.document_var).grid(
            row=2, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_document).grid(
            row=2, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Người ký").grid(
            row=3, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.signer_var).grid(
            row=3, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Label(
            form,
            text="Tên này được đưa vào metadata đã ký.",
            style="Muted.TLabel",
        ).grid(row=3, column=2, sticky="w", pady=4)

        ttk.Label(form, text="Tệp chữ ký (.sig)").grid(
            row=4, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.output_var).grid(
            row=4, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Lưu thành…", command=self._browse_output).grid(
            row=4, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="SHA-256").grid(
            row=5, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            form,
            textvariable=self.hash_var,
            state="readonly",
        ).grid(row=5, column=1, sticky="ew", padx=(8, 8), pady=4)
        hash_actions = ttk.Frame(form)
        hash_actions.grid(row=5, column=2, sticky="w", pady=4)
        self.hash_button = ttk.Button(
            hash_actions,
            text="Tính lại",
            command=self._hash_document,
        )
        self.hash_button.pack(side="left")
        ttk.Label(hash_actions, textvariable=self.size_var).pack(
            side="left", padx=(8, 0)
        )

        actions = ttk.Frame(form)
        actions.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.sign_button = ttk.Button(
            actions,
            text="Ký tài liệu",
            command=self._sign,
        )
        self.sign_button.pack(side="left")
        self.clear_button = ttk.Button(
            actions,
            text="Xóa form",
            command=self._clear,
        )
        self.clear_button.pack(side="left", padx=(8, 0))

        result = ttk.LabelFrame(self, text="Kết quả ký", padding=12)
        result.pack(fill="x", pady=(12, 0))
        result.columnconfigure(1, weight=1)

        ttk.Label(result, text="Tệp chữ ký").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            result,
            textvariable=self.package_var,
            state="readonly",
        ).grid(row=0, column=1, sticky="ew", padx=(8, 0), pady=4)

        ttk.Label(result, text="Fingerprint").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(
            result,
            textvariable=self.fingerprint_var,
            state="readonly",
        ).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=4)

        ttk.Label(result, text="Thời điểm ký").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Label(result, textvariable=self.signed_at_var).grid(
            row=2, column=1, sticky="w", padx=(8, 0), pady=4
        )

    def set_key_path(self, path: str | Path) -> None:
        self.key_var.set(str(path))
        self._update_state()

    def set_document(self, path: str | Path) -> None:
        self.document_var.set(str(path))
        self._update_state()

    def _browse_key(self) -> None:
        path = self.ask_open("Chọn khóa riêng", _JSON_FILTER)
        if path is not None:
            self.set_key_path(path)

    def _browse_document(self) -> None:
        path = self.ask_open("Chọn tài liệu cần ký", _DOCUMENT_FILTER)
        if path is None:
            return
        self.document_var.set(str(path))
        self.output_var.set(str(default_signature_path(path)))
        self._hash_document()
        self._update_state()

    def _browse_output(self) -> None:
        default_name = (
            self.output_var.get()
            or (
                f"{Path(self.document_var.get()).name}.sig"
                if self.document_var.get().strip()
                else "document.sig"
            )
        )
        target = self.ask_save("Lưu tệp chữ ký", default_name, _PACKAGE_FILTER)
        if target is not None:
            self.output_var.set(str(target))

    def _hash_document(self) -> None:
        text = self.document_var.get().strip()
        if not text:
            self.hash_var.set("—")
            self.size_var.set("—")
            return
        path = Path(text)
        if not _is_file(text):
            self.hash_var.set("—")
            self.size_var.set("—")
            return

        started = self.app.run_task(
            f"Đang tính SHA-256 cho {path.name}…",
            lambda: (path.resolve(), sha256_file(path), path.stat().st_size),
            self._on_hashed,
            error_title="Không đọc được tài liệu",
            widgets=(self.hash_button,),
        )
        if started:
            self.hash_var.set("Đang tính…")

    def _on_hashed(self, payload: tuple[Path, bytes, int]) -> None:
        path, digest, size = payload
        if not _is_file(self.document_var.get()):
            return
        current = Path(self.document_var.get().strip())
        if current.resolve() != path:
            return
        self.hash_var.set(digest.hex())
        self.size_var.set(format_size(size))
        self.app.set_status("Đã tính SHA-256.")

    def _sign(self) -> None:
        key_text = self.key_var.get().strip()
        document_text = self.document_var.get().strip()
        signer = self.signer_var.get().strip()
        if not key_text or not document_text or not signer:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Cần chọn khóa riêng, tài liệu và nhập tên người ký.",
                parent=self.app,
            )
            return

        key_path = Path(key_text)
        document_path = Path(document_text)
        password = self.password_var.get() or None
        output_text = self.output_var.get().strip()
        output_path = Path(output_text) if output_text else None

        def work() -> SignResult:
            key = KeyService.load_private(key_path, password=password)
            return SignService.sign_file(
                key,
                document_path,
                signer,
                output_path=output_path,
            )

        started = self.app.run_task(
            "Đang ký tài liệu…",
            work,
            self._on_signed,
            error_title="Không ký được tài liệu",
            widgets=(self.sign_button,),
        )
        if started:
            self.app.log(f"Bắt đầu ký '{document_path.name}' với người ký '{signer}'.")

    def _on_signed(self, result: SignResult) -> None:
        package = result.package
        self.package_path = result.package_path
        self.package_var.set(str(result.package_path))
        self.fingerprint_var.set(package.key_fingerprint)
        self.signed_at_var.set(package.signed_at)
        self.output_var.set(str(result.package_path))

        self.app.demo_tab.set_context(
            Path(self.document_var.get().strip()),
            result.package_path,
        )
        self._prepare_verification(result.package_path, package)
        self.app.log(
            f"Đã ký '{package.original_name}' — {package.signer} — "
            f"{package.key_fingerprint}"
        )
        self.app.set_status("Ký tài liệu thành công.")

    def _prepare_verification(
        self,
        package_path: Path,
        package: SignaturePackage,
    ) -> None:
        document = Path(self.document_var.get().strip())
        private_text = self.key_var.get().strip()
        candidate: Path | None = None
        if private_text:
            private_path = Path(private_text)
            possible = private_path.with_name(
                private_path.name.replace("_private.json", "_public.json")
            )
            if possible != private_path and possible.is_file():
                candidate = possible
        if candidate is not None:
            key_path: Path | None = candidate
            self.app.apply_key_context(
                public_path=candidate,
                fingerprint=package.key_fingerprint,
            )
        elif (
            self.app.last_public_path is not None
            and self.app.last_fingerprint == package.key_fingerprint
        ):
            key_path = self.app.last_public_path
        else:
            key_path = None

        self.app.verify_tab.set_inputs(
            document=document,
            package=package_path,
            key=key_path,
        )

    def _clear(self) -> None:
        self.document_var.set("")
        self.output_var.set("")
        self.signer_var.set("")
        self.hash_var.set("—")
        self.size_var.set("—")
        self.package_var.set("—")
        self.fingerprint_var.set("—")
        self.signed_at_var.set("—")
        self.package_path = None
        self._update_state()

    def _update_state(self) -> None:
        key_ok = _is_file(self.key_var.get())
        document_ok = _is_file(self.document_var.get())
        signer_ok = bool(self.signer_var.get().strip())
        self.set_enabled(
            self.sign_button,
            key_ok and document_ok and signer_ok,
        )


class VerifyTab(BaseTab):
    """Verify a document against a signature package."""

    def __init__(self, app: "DSIGApp") -> None:
        super().__init__(app)
        self.key_var = tk.StringVar()
        self.document_var = tk.StringVar()
        self.package_var = tk.StringVar()
        self.expected_signer_var = tk.StringVar()

        self.reason_var = tk.StringVar(value="—")
        self.message_var = tk.StringVar(value="")
        self.signer_var = tk.StringVar(value="—")
        self.original_name_var = tk.StringVar(value="—")
        self.signed_at_var = tk.StringVar(value="—")
        self.fingerprint_var = tk.StringVar(value="—")

        for variable in (self.key_var, self.document_var, self.package_var):
            variable.trace_add("write", lambda *_: self._update_state())

        self._build()
        self._update_state()

    def _build(self) -> None:
        form = ttk.LabelFrame(self, text="Thông tin xác thực", padding=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Khóa công khai").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.key_var).grid(
            row=0, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_key).grid(
            row=0, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Tài liệu").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.document_var).grid(
            row=1, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_document).grid(
            row=1, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Tệp chữ ký (.sig)").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.package_var).grid(
            row=2, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_package).grid(
            row=2, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Người ký mong đợi").grid(
            row=3, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.expected_signer_var).grid(
            row=3, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Label(
            form,
            text="Để trống nếu không kiểm tra người ký.",
            style="Muted.TLabel",
        ).grid(row=3, column=2, sticky="w", pady=4)

        actions = ttk.Frame(form)
        actions.grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.verify_button = ttk.Button(
            actions,
            text="Xác thực",
            command=self._verify,
        )
        self.verify_button.pack(side="left")
        self.clear_button = ttk.Button(
            actions,
            text="Xóa kết quả",
            command=self.clear_result,
        )
        self.clear_button.pack(side="left", padx=(8, 0))

        result = ttk.LabelFrame(self, text="Kết quả", padding=12)
        result.pack(fill="both", expand=True, pady=(12, 0))
        result.columnconfigure(0, weight=1)

        self.banner = tk.Label(
            result,
            text="Chưa xác thực",
            bg="#eceff1",
            fg="#37474f",
            font=(self.app.family, 15, "bold"),
            anchor="w",
            padx=12,
            pady=10,
        )
        self.banner.grid(row=0, column=0, sticky="ew")

        ttk.Label(
            result,
            textvariable=self.reason_var,
            font=(self.app.family, 10, "bold"),
        ).grid(row=1, column=0, sticky="w", pady=(10, 0))

        self.message_label = tk.Label(
            result,
            textvariable=self.message_var,
            anchor="w",
            justify="left",
            wraplength=820,
        )
        self.message_label.grid(row=2, column=0, sticky="ew", pady=(2, 8))

        details = ttk.Frame(result)
        details.grid(row=3, column=0, sticky="ew")
        details.columnconfigure(1, weight=1)

        rows = (
            ("Người ký", self.signer_var),
            ("Tên tệp gốc", self.original_name_var),
            ("Thời điểm ký", self.signed_at_var),
            ("Fingerprint", self.fingerprint_var),
        )
        for row_index, (label, variable) in enumerate(rows):
            ttk.Label(details, text=label).grid(
                row=row_index, column=0, sticky="w", pady=3
            )
            ttk.Entry(
                details,
                textvariable=variable,
                state="readonly",
            ).grid(row=row_index, column=1, sticky="ew", padx=(8, 0), pady=3)

    def set_key_path(self, path: str | Path) -> None:
        self.key_var.set(str(path))
        self._update_state()

    def set_inputs(
        self,
        *,
        document: str | Path | None = None,
        package: str | Path | None = None,
        key: str | Path | None = None,
    ) -> None:
        if key is not None:
            self.key_var.set(str(key))
        if document is not None:
            self.document_var.set(str(document))
            if not self.package_var.get().strip():
                self.package_var.set(str(default_signature_path(document)))
        if package is not None:
            self.package_var.set(str(package))
        self._update_state()

    def _browse_key(self) -> None:
        path = self.ask_open("Chọn khóa công khai", _JSON_FILTER)
        if path is not None:
            self.set_key_path(path)

    def _browse_document(self) -> None:
        path = self.ask_open("Chọn tài liệu cần xác thực", _DOCUMENT_FILTER)
        if path is None:
            return
        self.document_var.set(str(path))
        if not self.package_var.get().strip():
            self.package_var.set(str(default_signature_path(path)))
        self._update_state()

    def _browse_package(self) -> None:
        path = self.ask_open("Chọn tệp chữ ký", _PACKAGE_FILTER)
        if path is not None:
            self.package_var.set(str(path))
            self._update_state()

    def _verify(self) -> None:
        key_text = self.key_var.get().strip()
        document_text = self.document_var.get().strip()
        package_text = self.package_var.get().strip()
        if not key_text or not document_text or not package_text:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Cần chọn khóa công khai, tài liệu và tệp chữ ký.",
                parent=self.app,
            )
            return

        key_path = Path(key_text)
        document_path = Path(document_text)
        package_path = Path(package_text)
        expected = self.expected_signer_var.get().strip() or None

        def work() -> VerificationResult:
            public_key = KeyService.load_public(key_path)
            return VerifyService.verify_file(
                document_path,
                package_path,
                public_key,
                expected_signer=expected,
            )

        started = self.app.run_task(
            "Đang xác thực chữ ký…",
            work,
            self._apply_result,
            error_title="Không xác thực được",
            widgets=(self.verify_button,),
        )
        if started:
            self.app.log(f"Bắt đầu xác thực '{document_path.name}'.")

    def _apply_result(self, result: VerificationResult) -> None:
        if result.valid:
            self.banner.configure(
                text="✔  CHỮ KÝ HỢP LỆ",
                bg="#e8f5e9",
                fg="#1b5e20",
            )
            self.app.log(
                f"Xác thực thành công: {self.document_var.get()} — "
                f"{result.signer or 'không rõ người ký'}."
            )
            self.app.set_status("Chữ ký hợp lệ.")
        else:
            self.banner.configure(
                text="✘  CHỮ KÝ KHÔNG HỢP LỆ",
                bg="#ffebee",
                fg="#b71c1c",
            )
            self.app.log(
                f"Xác thực thất bại: {result.reason.value} — "
                f"{self.document_var.get()}"
            )
            self.app.set_status(f"Chữ ký không hợp lệ: {result.reason.value}.")

        self.reason_var.set(result.reason.value)
        self.message_var.set(result.message)
        self.signer_var.set(result.signer or "—")
        self.original_name_var.set(result.original_name or "—")
        self.signed_at_var.set(result.signed_at or "—")
        self.fingerprint_var.set(result.key_fingerprint or "—")

    def clear_result(self) -> None:
        self.banner.configure(
            text="Chưa xác thực",
            bg="#eceff1",
            fg="#37474f",
        )
        self.reason_var.set("—")
        self.message_var.set("")
        self.signer_var.set("—")
        self.original_name_var.set("—")
        self.signed_at_var.set("—")
        self.fingerprint_var.set("—")

    def _update_state(self) -> None:
        key_ok = _is_file(self.key_var.get())
        document_ok = _is_file(self.document_var.get())
        package_ok = bool(self.package_var.get().strip())
        self.set_enabled(self.verify_button, key_ok and document_ok and package_ok)


class DemoTab(BaseTab):
    """Create a tampered copy to demonstrate integrity checking."""

    def __init__(self, app: "DSIGApp") -> None:
        super().__init__(app)
        self.source_var = tk.StringVar()
        self.package_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.offset_var = tk.StringVar(value="0")
        self.bit_var = tk.StringVar(value="0")

        for variable in (self.source_var, self.package_var, self.output_var):
            variable.trace_add("write", lambda *_: self._update_state())

        self._build()
        self._update_state()

    def _build(self) -> None:
        intro = ttk.Label(
            self,
            text=(
                "Tạo một bản sao của tài liệu với đúng một bit bị đảo. "
                "Tệp gốc không bị thay đổi. Sau đó chuyển sang tab Xác thực "
                "để thấy chữ ký bị từ chối."
            ),
            wraplength=860,
            justify="left",
        )
        intro.pack(fill="x", pady=(0, 12))

        form = ttk.LabelFrame(self, text="Bản sao bị sửa đổi", padding=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Tài liệu gốc").grid(
            row=0, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.source_var).grid(
            row=0, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_source).grid(
            row=0, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Tệp .sig gốc").grid(
            row=1, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.package_var).grid(
            row=1, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Duyệt…", command=self._browse_package).grid(
            row=1, column=2, sticky="w", pady=4
        )

        ttk.Label(form, text="Tệp đầu ra").grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Entry(form, textvariable=self.output_var).grid(
            row=2, column=1, sticky="ew", padx=(8, 8), pady=4
        )
        ttk.Button(form, text="Lưu thành…", command=self._browse_output).grid(
            row=2, column=2, sticky="w", pady=4
        )

        options = ttk.Frame(form)
        options.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Label(options, text="Vị trí byte").pack(side="left")
        ttk.Spinbox(
            options,
            from_=0,
            to=10**9,
            textvariable=self.offset_var,
            width=10,
        ).pack(side="left", padx=(8, 16))
        ttk.Label(options, text="Bit (0–7)").pack(side="left")
        ttk.Spinbox(
            options,
            from_=0,
            to=7,
            textvariable=self.bit_var,
            width=4,
        ).pack(side="left", padx=(8, 0))

        actions = ttk.Frame(form)
        actions.grid(row=4, column=0, columnspan=3, sticky="w", pady=(12, 0))
        self.create_button = ttk.Button(
            actions,
            text="Tạo bản sửa đổi",
            command=self._create,
        )
        self.create_button.pack(side="left")
        self.clear_button = ttk.Button(
            actions,
            text="Xóa form",
            command=self._clear,
        )
        self.clear_button.pack(side="left", padx=(8, 0))

        note = ttk.Label(
            self,
            text=(
                "Gợi ý: ký một tài liệu ở tab Ký, sau đó quay lại tab này — "
                "đường dẫn tài liệu và tệp .sig sẽ được điền tự động."
            ),
            style="Muted.TLabel",
            wraplength=860,
            justify="left",
        )
        note.pack(fill="x", pady=(12, 0))

    def set_context(self, document: str | Path, package: str | Path) -> None:
        self.source_var.set(str(document))
        self.package_var.set(str(package))
        self.output_var.set(str(default_tampered_path(document)))
        self._update_state()

    def _browse_source(self) -> None:
        path = self.ask_open("Chọn tài liệu gốc", _DOCUMENT_FILTER)
        if path is None:
            return
        self.source_var.set(str(path))
        if not self.package_var.get().strip():
            self.package_var.set(str(default_signature_path(path)))
        self.output_var.set(str(default_tampered_path(path)))
        self._update_state()

    def _browse_package(self) -> None:
        path = self.ask_open("Chọn tệp chữ ký gốc", _PACKAGE_FILTER)
        if path is not None:
            self.package_var.set(str(path))
            self._update_state()

    def _browse_output(self) -> None:
        default_name = self.output_var.get() or "document-tampered.pdf"
        target = self.ask_save("Lưu bản sửa đổi", default_name, _DOCUMENT_FILTER)
        if target is not None:
            self.output_var.set(str(target))

    def _create(self) -> None:
        source_text = self.source_var.get().strip()
        package_text = self.package_var.get().strip()
        if not source_text or not package_text:
            messagebox.showwarning(
                "Thiếu thông tin",
                "Cần chọn tài liệu gốc và tệp chữ ký .sig.",
                parent=self.app,
            )
            return

        source = Path(source_text)
        package = Path(package_text)
        if not package.is_file():
            messagebox.showerror(
                "Không tìm thấy tệp chữ ký",
                f"Tệp .sig không tồn tại:\n{package}",
                parent=self.app,
            )
            return

        try:
            offset = parse_integer(
                self.offset_var.get(),
                label="Vị trí byte",
                minimum=0,
            )
            bit = parse_integer(
                self.bit_var.get(),
                label="Bit",
                minimum=0,
                maximum=7,
            )
        except ValueError as exc:
            messagebox.showerror("Giá trị không hợp lệ", str(exc), parent=self.app)
            return

        output_text = self.output_var.get().strip()
        output = Path(output_text) if output_text else default_tampered_path(source)

        started = self.app.run_task(
            f"Đang tạo bản sửa đổi cho {source.name}…",
            lambda: flip_bit(source, output, offset=offset, bit=bit),
            lambda path: self._on_created(path, package),
            error_title="Không tạo được bản sửa đổi",
            widgets=(self.create_button,),
        )
        if started:
            self.app.log(f"Đang tạo bản sửa đổi: {source} → {output}")

    def _on_created(self, output: Path, package: Path) -> None:
        self.app.log(f"Đã tạo bản sửa đổi: {output}")
        self.app.verify_tab.set_inputs(
            document=output,
            package=package,
            key=self.app.last_public_path,
        )
        self.app.notebook.select(self.app.verify_tab)
        self.app.set_status(
            "Đã tạo bản sửa đổi. Nhấn 'Xác thực' để kiểm tra chữ ký."
        )

    def _clear(self) -> None:
        self.source_var.set("")
        self.package_var.set("")
        self.output_var.set("")
        self.offset_var.set("0")
        self.bit_var.set("0")
        self._update_state()

    def _update_state(self) -> None:
        source_ok = _is_file(self.source_var.get())
        package_ok = _is_file(self.package_var.get())
        self.set_enabled(self.create_button, source_ok and package_ok)


class DSIGApp(tk.Tk):
    """Main application window with keys, signing, verification and demo tabs."""

    def __init__(self) -> None:
        super().__init__()
        self._closing = False
        self._task_running = False
        self._task_queue: queue.Queue[tuple[str, Any]] = queue.Queue()

        self.last_private_path: Path | None = None
        self.last_public_path: Path | None = None
        self.last_fingerprint: str | None = None

        self.title("DSIG — Ký số tài liệu phê duyệt")
        self.geometry("1040x780")
        self.minsize(920, 700)

        self._configure_style()
        self._build_menu()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")

        self.family = tkfont.nametofont("TkDefaultFont").actual("family")
        tkfont.nametofont("TkDefaultFont").configure(size=10)
        tkfont.nametofont("TkTextFont").configure(size=10)
        tkfont.nametofont("TkFixedFont").configure(size=9)

        style.configure("Title.TLabel", font=(self.family, 22, "bold"))
        style.configure(
            "Subtitle.TLabel",
            font=(self.family, 10),
            foreground="#546e7a",
        )
        style.configure("Muted.TLabel", foreground="#607d8b")
        style.configure("Heading.TLabel", font=(self.family, 11, "bold"))

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Thoát", command=self._on_close)
        menubar.add_cascade(label="Tệp", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Giới thiệu DSIG", command=self._show_about)
        menubar.add_cascade(label="Trợ giúp", menu=help_menu)
        self.configure(menu=menubar)

    def _build(self) -> None:
        header = ttk.Frame(self, padding=(18, 14, 18, 6))
        header.pack(fill="x")

        ttk.Label(header, text="DSIG", style="Title.TLabel").pack(side="left")
        titles = ttk.Frame(header)
        titles.pack(side="left", padx=(16, 0), pady=(4, 0))
        ttk.Label(
            titles,
            text="Ký số tài liệu phê duyệt",
            font=(self.family, 12, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            titles,
            text="RSA-2048 · SHA-256 · EMSA-PKCS1-v1_5 · TBS metadata",
            style="Subtitle.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            header,
            text=f"v{__version__}",
            style="Muted.TLabel",
        ).pack(side="right", anchor="n", pady=(6, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        self.key_tab = KeyTab(self)
        self.sign_tab = SignTab(self)
        self.verify_tab = VerifyTab(self)
        self.demo_tab = DemoTab(self)
        self.notebook.add(self.key_tab, text="  Khóa  ")
        self.notebook.add(self.sign_tab, text="  Ký tài liệu  ")
        self.notebook.add(self.verify_tab, text="  Xác thực  ")
        self.notebook.add(self.demo_tab, text="  Demo sửa đổi  ")

        log_frame = ttk.LabelFrame(self, text="Nhật ký hoạt động", padding=(8, 4))
        log_frame.pack(fill="x", padx=16, pady=(0, 4))
        self.log_text = tk.Text(
            log_frame,
            height=5,
            wrap="word",
            state="disabled",
            relief="flat",
            bg="#f7f9fa",
            fg="#37474f",
        )
        log_scroll = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="x", expand=True)
        log_scroll.pack(side="right", fill="y")
        ttk.Button(
            log_frame,
            text="Xóa",
            command=self.clear_log,
        ).pack(side="right", padx=(8, 4))

        status_bar = ttk.Frame(self, padding=(16, 2, 16, 8))
        status_bar.pack(fill="x")
        self.status_var = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(
            status_bar,
            textvariable=self.status_var,
            style="Muted.TLabel",
        ).pack(side="left")

        self.log("DSIG đã khởi động.")
        self.log("Chọn hoặc tạo khóa, sau đó ký và xác thực tài liệu.")

    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def log(self, message: str) -> None:
        if self._closing:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def run_task(
        self,
        message: str,
        work: Callable[[], Any],
        on_success: Callable[[Any], None],
        *,
        error_title: str = "Lỗi",
        widgets: Sequence[ttk.Widget] = (),
    ) -> bool:
        """Run ``work`` on a worker thread and deliver the result on the UI thread."""

        if self._closing or self._task_running:
            if self._task_running:
                self.set_status("Đang xử lý tác vụ khác, vui lòng đợi…")
            return False

        self._task_running = True
        self.set_status(message)
        for widget in widgets:
            widget.state(["disabled"])

        def runner() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - reported to the user
                self._task_queue.put(("error", exc))
            else:
                self._task_queue.put(("ok", result))

        threading.Thread(target=runner, daemon=True).start()
        self.after(80, self._poll_task, on_success, error_title, tuple(widgets))
        return True

    def _poll_task(
        self,
        on_success: Callable[[Any], None],
        error_title: str,
        widgets: tuple[ttk.Widget, ...],
    ) -> None:
        if self._closing:
            return

        try:
            kind, payload = self._task_queue.get_nowait()
        except queue.Empty:
            self.after(80, self._poll_task, on_success, error_title, widgets)
            return

        self._task_running = False
        for widget in widgets:
            try:
                widget.state(["!disabled"])
            except tk.TclError:
                pass

        if kind == "ok":
            try:
                on_success(payload)
            except Exception as exc:  # noqa: BLE001 - reported to the user
                self._handle_task_error(exc, error_title)
        else:
            self._handle_task_error(payload, error_title)

    def _handle_task_error(self, exc: BaseException, title: str) -> None:
        self.set_status(f"Lỗi: {exc}")
        self.log(f"LỖI: {exc}")
        messagebox.showerror(title, str(exc), parent=self)

    def apply_key_context(
        self,
        *,
        private_path: str | Path | None = None,
        public_path: str | Path | None = None,
        fingerprint: str | None = None,
    ) -> None:
        if private_path is not None:
            self.last_private_path = Path(private_path)
            self.sign_tab.set_key_path(private_path)
        if public_path is not None:
            self.last_public_path = Path(public_path)
            self.verify_tab.set_key_path(public_path)
        if fingerprint is not None:
            self.last_fingerprint = fingerprint

    def _show_about(self) -> None:
        messagebox.showinfo(
            "Giới thiệu DSIG",
            (
                f"DSIG {__version__}\n\n"
                "Ký số tài liệu phê duyệt với RSA-2048, SHA-256 và "
                "EMSA-PKCS1-v1_5.\n"
                "Metadata (người ký, tên tệp, kích thước, thời gian) "
                "được ràng buộc trong TBS.\n\n"
                "Nhật ký hoạt động ở cuối cửa sổ ghi lại các thao tác."
            ),
            parent=self,
        )

    def _on_close(self) -> None:
        self._closing = True
        self.destroy()


def main() -> int:
    app = DSIGApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
