"""Integration tests for the ``dsig`` command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import cli

DOCUMENT = b"approval amount: 1000 USD"


def _generate(tmp_path: Path, capsys, name: str = "alice", *extra: str) -> dict:
    code = cli.main(
        [
            "keygen",
            "--name",
            name,
            "--bits",
            "1024",
            "--keys-dir",
            str(tmp_path / "keys"),
            "--json",
            *extra,
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_OK, captured.err
    return json.loads(captured.out)


def _sign(
    tmp_path: Path,
    capsys,
    document: Path,
    *extra: str,
    signer: str = "Alice",
) -> tuple[int, dict | None, str]:
    code = cli.main(
        [
            "sign",
            "--key",
            str(tmp_path / "keys" / "alice_private.json"),
            "--file",
            str(document),
            "--signer",
            signer,
            "--json",
            *extra,
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else None
    return code, payload, captured.err


def _verify_json(
    capsys,
    tmp_path: Path,
    document: Path,
    package: Path,
    *extra: str,
    key: str = "alice_public.json",
) -> tuple[int, dict, str]:
    code = cli.main(
        [
            "verify",
            "--key",
            str(tmp_path / "keys" / key),
            "--file",
            str(document),
            "--sig",
            str(package),
            "--json",
            *extra,
        ]
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out) if captured.out.strip() else {}
    return code, payload, captured.err


@pytest.fixture
def signed(tmp_path, capsys):
    payload = _generate(tmp_path, capsys)
    document = tmp_path / "contract.txt"
    document.write_bytes(DOCUMENT)
    code, signed_payload, error = _sign(tmp_path, capsys, document)
    assert code == cli.EXIT_OK, error
    assert signed_payload is not None
    package = Path(signed_payload["package"])
    return {
        "key": payload,
        "document": document,
        "package": package,
        "signed": signed_payload,
    }


def test_keygen_json_creates_key_files(tmp_path, capsys) -> None:
    payload = _generate(tmp_path, capsys)

    assert payload["ok"] is True
    assert payload["name"] == "alice"
    assert payload["bits"] == 1024
    assert payload["encrypted"] is False
    assert payload["fingerprint"].startswith("sha256:")
    assert Path(payload["private_key"]).is_file()
    assert Path(payload["public_key"]).is_file()


def test_keygen_refuses_to_overwrite_without_force(tmp_path, capsys) -> None:
    _generate(tmp_path, capsys)

    code = cli.main(
        [
            "keygen",
            "--name",
            "alice",
            "--bits",
            "1024",
            "--keys-dir",
            str(tmp_path / "keys"),
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "already exists" in captured.err

    code = cli.main(
        [
            "keygen",
            "--name",
            "alice",
            "--bits",
            "1024",
            "--keys-dir",
            str(tmp_path / "keys"),
            "--force",
        ]
    )
    assert code == cli.EXIT_OK


def test_keygen_rejects_invalid_name(tmp_path, capsys) -> None:
    code = cli.main(
        [
            "keygen",
            "--name",
            "../alice",
            "--keys-dir",
            str(tmp_path / "keys"),
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "key name" in captured.err


def test_sign_verify_roundtrip(tmp_path, capsys, signed) -> None:
    assert signed["package"] == signed["document"].with_name(
        signed["document"].name + ".sig"
    )
    assert signed["package"].is_file()
    assert signed["signed"]["sha256"]

    code, payload, error = _verify_json(
        capsys,
        tmp_path,
        signed["document"],
        signed["package"],
    )
    assert code == cli.EXIT_OK, error
    assert payload["valid"] is True
    assert payload["reason"] == "VALID"
    assert payload["signer"] == "Alice"
    assert payload["original_name"] == "contract.txt"


def test_sign_custom_output(tmp_path, capsys, signed) -> None:
    output = tmp_path / "packages" / "approval.sig"
    code, payload, error = _sign(
        tmp_path,
        capsys,
        signed["document"],
        "--out",
        str(output),
    )
    assert code == cli.EXIT_OK, error
    assert output.is_file()
    assert payload is not None
    assert Path(payload["package"]) == output


def test_verify_tampered_document_exits_1(tmp_path, capsys, signed) -> None:
    tampered = tmp_path / "tampered.txt"

    code = cli.main(
        [
            "tamper",
            "--file",
            str(signed["document"]),
            "--out",
            str(tampered),
            "--offset",
            "20",
        ]
    )
    assert code == cli.EXIT_OK
    capsys.readouterr()

    code, payload, _ = _verify_json(
        capsys,
        tmp_path,
        tampered,
        signed["package"],
    )
    assert code == cli.EXIT_INVALID
    assert payload["valid"] is False
    assert payload["reason"] == "HASH_MISMATCH"


def test_verify_wrong_key_exits_1(tmp_path, capsys, signed) -> None:
    _generate(tmp_path, capsys, "bob")

    code, payload, _ = _verify_json(
        capsys,
        tmp_path,
        signed["document"],
        signed["package"],
        key="bob_public.json",
    )
    assert code == cli.EXIT_INVALID
    assert payload["reason"] == "KEY_MISMATCH"


def test_verify_expected_signer(tmp_path, capsys, signed) -> None:
    code, payload, _ = _verify_json(
        capsys,
        tmp_path,
        signed["document"],
        signed["package"],
        "--signer",
        "Bob",
    )
    assert code == cli.EXIT_INVALID
    assert payload["reason"] == "SIGNER_MISMATCH"


def test_verify_missing_package_exits_1(tmp_path, capsys, signed) -> None:
    code, payload, _ = _verify_json(
        capsys,
        tmp_path,
        signed["document"],
        tmp_path / "missing.sig",
    )
    assert code == cli.EXIT_INVALID
    assert payload["reason"] == "PACKAGE_NOT_FOUND"


def test_verify_missing_public_key_exits_2(tmp_path, capsys, signed) -> None:
    code = cli.main(
        [
            "verify",
            "--key",
            str(tmp_path / "keys" / "missing.json"),
            "--file",
            str(signed["document"]),
            "--sig",
            str(signed["package"]),
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "error:" in captured.err


def test_inspect_json(tmp_path, capsys, signed) -> None:
    code = cli.main(["inspect", "--sig", str(signed["package"]), "--json"])
    captured = capsys.readouterr()

    assert code == cli.EXIT_OK
    payload = json.loads(captured.out)
    assert payload["format"] == "DSIG/1"
    assert payload["algorithm"] == "RSA-PKCS1v15-SHA256"
    assert payload["signer"] == "Alice"
    assert payload["signature_bytes"] == 128


def test_inspect_malformed_package_exits_2(tmp_path, capsys) -> None:
    broken = tmp_path / "broken.sig"
    broken.write_text("{not json", encoding="utf-8")

    code = cli.main(["inspect", "--sig", str(broken)])
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "error:" in captured.err


def test_sign_missing_document_exits_2(tmp_path, capsys) -> None:
    _generate(tmp_path, capsys)

    code, payload, error = _sign(
        tmp_path,
        capsys,
        tmp_path / "missing.txt",
    )
    assert code == cli.EXIT_ERROR
    assert payload is None
    assert "error:" in error


def test_tamper_preserves_source_and_rejects_same_output(
    tmp_path, capsys, signed
) -> None:
    original = signed["document"].read_bytes()
    modified = tmp_path / "modified.txt"

    code = cli.main(
        [
            "tamper",
            "--file",
            str(signed["document"]),
            "--out",
            str(modified),
            "--offset",
            "0",
            "--bit",
            "0",
        ]
    )
    assert code == cli.EXIT_OK
    capsys.readouterr()
    assert signed["document"].read_bytes() == original
    assert modified.read_bytes() != original

    code = cli.main(
        [
            "tamper",
            "--file",
            str(signed["document"]),
            "--out",
            str(signed["document"]),
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "refusing to overwrite" in captured.err
    assert signed["document"].read_bytes() == original


def test_tamper_rejects_out_of_range_offset(tmp_path, capsys, signed) -> None:
    code = cli.main(
        [
            "tamper",
            "--file",
            str(signed["document"]),
            "--out",
            str(tmp_path / "out.txt"),
            "--offset",
            "9999",
        ]
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_ERROR
    assert "offset" in captured.err


def test_fingerprint_private_and_public_match(tmp_path, capsys, signed) -> None:
    outputs = []
    for filename in ("alice_public.json", "alice_private.json"):
        code = cli.main(
            [
                "fingerprint",
                "--key",
                str(tmp_path / "keys" / filename),
            ]
        )
        captured = capsys.readouterr()
        assert code == cli.EXIT_OK
        outputs.append(captured.out.strip())

    assert outputs[0] == outputs[1] == signed["key"]["fingerprint"]


def test_password_protected_key_roundtrip(tmp_path, capsys) -> None:
    pytest.importorskip("cryptography")
    password_file = tmp_path / "password.txt"
    password_file.write_text("correct horse battery staple\n", encoding="utf-8")

    payload = _generate(
        tmp_path,
        capsys,
        "alice",
        "--password-file",
        str(password_file),
    )
    assert payload["encrypted"] is True

    document = tmp_path / "contract.txt"
    document.write_bytes(DOCUMENT)
    code, signed_payload, error = _sign(
        tmp_path,
        capsys,
        document,
        "--password-file",
        str(password_file),
    )
    assert code == cli.EXIT_OK, error
    assert signed_payload is not None

    code, payload, _ = _verify_json(
        capsys,
        tmp_path,
        document,
        Path(signed_payload["package"]),
    )
    assert code == cli.EXIT_OK
    assert payload["valid"] is True

    code, payload, error = _sign(tmp_path, capsys, document, "--password", "wrong")
    assert code == cli.EXIT_ERROR
    assert payload is None
    assert "wrong password" in error


def test_version_and_required_command(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])
    assert excinfo.value.code == 0
    capsys.readouterr()

    with pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2
