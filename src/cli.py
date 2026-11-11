"""Command-line interface for document signing and verification.

The CLI is intentionally thin: it parses arguments, resolves passwords and
delegates all cryptographic work to the service layer.  Exit codes are stable
so the tool can be used in scripts and CI:

* ``0`` — command succeeded (and the signature is valid for ``verify``);
* ``1`` — verification failed (invalid or malformed signature);
* ``2`` — usage, I/O, key or package error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from src import __version__
from src.models.signature_package import PackageError
from src.services.file_service import flip_bit
from src.services.key_service import KeyFileError, KeyService, validate_key_name
from src.services.package_service import read_package
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_ERROR = 2

_PROMPT = object()


def _add_password_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--password",
        nargs="?",
        const=_PROMPT,
        default=None,
        metavar="PASSWORD",
        help=(
            "password for an encrypted private key; omit the value to be "
            "prompted securely (a literal value is visible in shell history)"
        ),
    )
    group.add_argument(
        "--password-file",
        type=Path,
        metavar="PATH",
        help="read the password from the first line of PATH",
    )


def _resolve_password(args: argparse.Namespace) -> str | None:
    password_file = getattr(args, "password_file", None)
    if password_file is not None:
        lines = Path(password_file).read_text(encoding="utf-8").splitlines()
        if not lines or not lines[0]:
            raise ValueError(f"password file is empty: {password_file}")
        return lines[0]

    password = getattr(args, "password", None)
    if password is _PROMPT:
        prompted = getpass.getpass("Password: ")
        if not prompted:
            raise ValueError("password must not be empty")
        return prompted
    return password


def _print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _key_payload(generated: Any, *, encrypted: bool) -> dict[str, object]:
    return {
        "ok": True,
        "name": generated.private_path.name.removesuffix("_private.json"),
        "bits": generated.private_key.key_size,
        "fingerprint": generated.fingerprint,
        "private_key": str(generated.private_path),
        "public_key": str(generated.public_path),
        "encrypted": encrypted,
    }


def _cmd_keygen(args: argparse.Namespace) -> int:
    name = validate_key_name(args.name)
    directory = Path(args.keys_dir)
    private_path = directory / f"{name}_private.json"
    public_path = directory / f"{name}_public.json"

    if not args.force and (private_path.exists() or public_path.exists()):
        raise ValueError(
            f"key '{name}' already exists in {directory}; use --force to overwrite"
        )

    password = _resolve_password(args)
    generated = KeyService.generate(
        name,
        bits=args.bits,
        keys_dir=directory,
        password=password,
    )
    payload = _key_payload(generated, encrypted=password is not None)

    if args.json:
        _print_json(payload)
    else:
        print(f"Generated RSA-{generated.private_key.key_size} key '{name}'")
        print(f"Fingerprint: {generated.fingerprint}")
        print(f"Private key: {generated.private_path}")
        print(f"Public key:  {generated.public_path}")
        if password is not None:
            print("The private key is protected with a password.")
        else:
            print("Keep the private key secret; it is not encrypted.")
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    password = _resolve_password(args)
    private_key = KeyService.load_private(args.key, password=password)
    result = SignService.sign_file(
        private_key,
        args.file,
        args.signer,
        output_path=args.out,
        signed_at=args.signed_at,
    )
    package = result.package

    payload = {
        "ok": True,
        "document": str(Path(args.file)),
        "package": str(result.package_path),
        "signer": package.signer,
        "key_fingerprint": package.key_fingerprint,
        "original_name": package.original_name,
        "size": package.size,
        "sha256": package.file_sha256,
        "signed_at": package.signed_at,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"Signed: {args.file}")
        print(f"Package: {result.package_path}")
        print(f"Signer:  {package.signer}")
        print(f"Fingerprint: {package.key_fingerprint}")
        print(f"SHA-256: {package.file_sha256}")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    public_key = KeyService.load_public(args.key)
    result = VerifyService.verify_file(
        args.file,
        args.sig,
        public_key,
        expected_signer=args.signer,
    )

    payload = {
        **result.as_dict(),
        "document": str(Path(args.file)),
        "package": str(Path(args.sig)),
    }
    if args.json:
        _print_json(payload)
    elif result.valid:
        print(f"VALID: {args.file}")
        print(f"Signer: {result.signer}")
        print(f"Signed at: {result.signed_at}")
        print(f"Fingerprint: {result.key_fingerprint}")
    else:
        print(f"INVALID: {result.reason.value}")
        print(f"Document: {args.file}")
        print(result.message)

    return EXIT_OK if result.valid else EXIT_INVALID


def _cmd_inspect(args: argparse.Namespace) -> int:
    package = read_package(args.sig)
    payload = {
        **package.to_dict(),
        "signature_bytes": len(package.signature),
    }

    if args.json:
        _print_json(payload)
    else:
        print(f"Package: {args.sig}")
        print(f"Format: {package.format}")
        print(f"Algorithm: {package.algorithm}")
        print(f"Signer: {package.signer}")
        print(f"Fingerprint: {package.key_fingerprint}")
        print(f"File: {package.original_name} ({package.size} bytes)")
        print(f"SHA-256: {package.file_sha256}")
        print(f"Signed at: {package.signed_at}")
        print(f"Signature: {len(package.signature)} bytes")
    return EXIT_OK


def _key_format(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise KeyFileError(f"cannot read key file: {path}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeyFileError("key file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise KeyFileError("key file must contain a JSON object")
    return str(data.get("format"))


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    path = Path(args.key)
    key_format = _key_format(path)

    if key_format == "RSA-PUB/1":
        fingerprint = KeyService.load_public(path).fingerprint
    elif key_format in {"RSA-PRIV/1", "RSA-PRIV-ENC/1"}:
        password = _resolve_password(args)
        private_key = KeyService.load_private(path, password=password)
        fingerprint = private_key.public_key.fingerprint
    else:
        raise KeyFileError(f"unsupported key format: {key_format!r}")

    if args.json:
        _print_json({"fingerprint": fingerprint, "key": str(path)})
    else:
        print(fingerprint)
    return EXIT_OK


def _cmd_tamper(args: argparse.Namespace) -> int:
    source = Path(args.file)
    output = flip_bit(
        source,
        args.out,
        offset=args.offset,
        bit=args.bit,
    )

    payload = {
        "ok": True,
        "source": str(source),
        "output": str(output),
        "offset": args.offset,
        "bit": args.bit,
    }
    if args.json:
        _print_json(payload)
    else:
        print(f"Flipped bit {args.bit} at offset {args.offset}")
        print(f"Source: {source}")
        print(f"Output: {output}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dsig",
        description=(
            "Sign and verify documents with RSA-2048, SHA-256 and "
            "EMSA-PKCS1-v1_5."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
    )

    keygen = subparsers.add_parser(
        "keygen",
        help="generate an RSA key pair",
        description="Generate a private/public key pair and save it as JSON.",
    )
    keygen.add_argument("--name", required=True, help="key name, e.g. alice")
    keygen.add_argument(
        "--bits",
        type=int,
        default=2048,
        metavar="N",
        help="modulus size in bits (default: 2048; use 1024 only for tests)",
    )
    keygen.add_argument(
        "--keys-dir",
        default="keys",
        metavar="DIR",
        help="output directory for key files (default: keys)",
    )
    keygen.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing key files",
    )
    _add_password_options(keygen)
    keygen.add_argument("--json", action="store_true", help="emit JSON")
    keygen.set_defaults(handler=_cmd_keygen)

    sign = subparsers.add_parser(
        "sign",
        help="sign a document and create a .sig package",
        description=(
            "Sign a document with a private key.  The signature binds the "
            "document digest to the signer, filename, size and timestamp."
        ),
    )
    sign.add_argument("--key", required=True, type=Path, help="private key JSON")
    sign.add_argument("--file", required=True, type=Path, help="document to sign")
    sign.add_argument(
        "--signer",
        required=True,
        help="signer identity stored in the signed metadata",
    )
    sign.add_argument(
        "--out",
        type=Path,
        metavar="PATH",
        help="package path (default: <document>.sig)",
    )
    sign.add_argument(
        "--signed-at",
        metavar="TIMESTAMP",
        help="override the signing time (ISO-8601 with UTC offset)",
    )
    _add_password_options(sign)
    sign.add_argument("--json", action="store_true", help="emit JSON")
    sign.set_defaults(handler=_cmd_sign)

    verify = subparsers.add_parser(
        "verify",
        help="verify a document against a .sig package",
        description=(
            "Verify the document digest, signature padding, TBS metadata and "
            "key fingerprint.  Exit status is 0 for a valid signature and 1 "
            "for an invalid one."
        ),
    )
    verify.add_argument("--key", required=True, type=Path, help="public key JSON")
    verify.add_argument("--file", required=True, type=Path, help="document to verify")
    verify.add_argument("--sig", required=True, type=Path, help="signature package")
    verify.add_argument(
        "--signer",
        metavar="NAME",
        help="require this signer identity",
    )
    verify.add_argument("--json", action="store_true", help="emit JSON")
    verify.set_defaults(handler=_cmd_verify)

    inspect = subparsers.add_parser(
        "inspect",
        help="print package metadata without verifying",
        description="Parse a .sig package and display its metadata.",
    )
    inspect.add_argument("--sig", required=True, type=Path, help="signature package")
    inspect.add_argument("--json", action="store_true", help="emit JSON")
    inspect.set_defaults(handler=_cmd_inspect)

    fingerprint = subparsers.add_parser(
        "fingerprint",
        help="print the fingerprint of a key",
        description="Read a public or private key file and print its fingerprint.",
    )
    fingerprint.add_argument("--key", required=True, type=Path, help="key JSON")
    _add_password_options(fingerprint)
    fingerprint.add_argument("--json", action="store_true", help="emit JSON")
    fingerprint.set_defaults(handler=_cmd_fingerprint)

    tamper = subparsers.add_parser(
        "tamper",
        help="flip one bit in a file (demo helper)",
        description=(
            "Create a modified copy of a document with one bit flipped.  "
            "Useful for demonstrating that verification detects changes."
        ),
    )
    tamper.add_argument("--file", required=True, type=Path, help="source document")
    tamper.add_argument("--out", required=True, type=Path, help="modified copy")
    tamper.add_argument(
        "--offset",
        type=int,
        default=0,
        metavar="N",
        help="byte offset to modify (default: 0)",
    )
    tamper.add_argument(
        "--bit",
        type=int,
        default=0,
        metavar="N",
        help="bit position 0-7 to flip (default: 0)",
    )
    tamper.add_argument("--json", action="store_true", help="emit JSON")
    tamper.set_defaults(handler=_cmd_tamper)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.handler(args))
    except (KeyFileError, PackageError, OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
