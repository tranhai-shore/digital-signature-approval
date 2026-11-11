"""Key generation, storage and optional password protection."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from src.crypto.encoding import b64url_decode, b64url_encode
from src.crypto.rsa import RSAPrivateKey, RSAPublicKey, generate_keypair
from src.models.json_support import JSONSupportError, loads_strict, read_json_file
from src.models.signature_package import validate_fingerprint
from src.services.file_service import atomic_write_text

ENCRYPTED_PRIVATE_FORMAT = "RSA-PRIV-ENC/1"
KDF_NAME = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12
MIN_KDF_ITERATIONS = 10_000
MAX_KDF_ITERATIONS = 2_000_000

_KEY_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class KeyFileError(ValueError):
    """Raised when a key file is missing, malformed or cannot be decrypted."""


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    private_key: RSAPrivateKey
    private_path: Path
    public_path: Path

    @property
    def fingerprint(self) -> str:
        return self.private_key.public_key.fingerprint


def validate_key_name(value: str) -> str:
    """Allow simple names such as ``alice`` or ``team.alice-01``."""

    if not isinstance(value, str) or not _KEY_NAME_RE.fullmatch(value):
        raise ValueError(
            "key name must start with a letter/digit and contain only "
            "letters, digits, '.', '_' or '-' (max 64 characters)"
        )
    return value


def _read_json_object(path: str | Path) -> dict[str, object]:
    target = Path(path)
    try:
        data = read_json_file(target)
    except OSError as exc:
        raise KeyFileError(f"cannot read key file: {target}") from exc
    except JSONSupportError as exc:
        raise KeyFileError(f"key file is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise KeyFileError("key file must contain a JSON object")
    return data


def _crypto_primitives():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise KeyFileError(
            "cài gói 'cryptography' để dùng mật khẩu bảo vệ khóa riêng"
        ) from exc
    return InvalidTag, hashes, AESGCM, PBKDF2HMAC


def _encrypt_private_key(
    key: RSAPrivateKey,
    password: str,
) -> dict[str, object]:
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")

    _, hashes, AESGCM, PBKDF2HMAC = _crypto_primitives()
    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)

    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    ).derive(password.encode("utf-8"))

    plaintext = json.dumps(
        key.to_dict(),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint = key.public_key.fingerprint
    associated_data = ENCRYPTED_PRIVATE_FORMAT.encode("ascii") + fingerprint.encode(
        "ascii"
    )

    encrypted = AESGCM(derived).encrypt(nonce, plaintext, associated_data)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]

    return {
        "format": ENCRYPTED_PRIVATE_FORMAT,
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "salt": b64url_encode(salt),
        "nonce": b64url_encode(nonce),
        "ciphertext": b64url_encode(ciphertext),
        "tag": b64url_encode(tag),
        "public_fingerprint": fingerprint,
    }


def _decrypt_private_key(
    data: dict[str, object],
    password: str | None,
) -> RSAPrivateKey:
    if not password:
        raise KeyFileError("private key is encrypted; a password is required")
    if data.get("kdf") != KDF_NAME:
        raise KeyFileError("unsupported key-derivation function")

    iterations = data.get("iterations")
    if (
        isinstance(iterations, bool)
        or not isinstance(iterations, int)
        or not MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS
    ):
        raise KeyFileError("invalid PBKDF2 iteration count")

    try:
        fingerprint = validate_fingerprint(str(data["public_fingerprint"]))
        salt = b64url_decode(str(data["salt"]))
        nonce = b64url_decode(str(data["nonce"]))
        ciphertext = b64url_decode(str(data["ciphertext"]))
        tag = b64url_decode(str(data["tag"]))
    except KeyError as exc:
        raise KeyFileError(f"missing encrypted-key field: {exc.args[0]}") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, KeyFileError):
            raise
        raise KeyFileError("encrypted key contains invalid values") from exc

    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(tag) != 16:
        raise KeyFileError("encrypted key has invalid salt/nonce/tag length")

    InvalidTag, hashes, AESGCM, PBKDF2HMAC = _crypto_primitives()
    derived = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    ).derive(password.encode("utf-8"))

    associated_data = ENCRYPTED_PRIVATE_FORMAT.encode("ascii") + fingerprint.encode(
        "ascii"
    )
    try:
        plaintext = AESGCM(derived).decrypt(
            nonce,
            ciphertext + tag,
            associated_data,
        )
    except InvalidTag as exc:
        raise KeyFileError("wrong password or corrupted private key") from exc

    try:
        key_data = loads_strict(plaintext)
        if not isinstance(key_data, dict):
            raise KeyFileError("decrypted key is not a JSON object")
        key = RSAPrivateKey.from_dict(key_data)
    except (KeyFileError, JSONSupportError, ValueError) as exc:
        if isinstance(exc, KeyFileError):
            raise
        raise KeyFileError("decrypted key is malformed") from exc

    if key.public_key.fingerprint != fingerprint:
        raise KeyFileError("decrypted key fingerprint does not match envelope")
    return key


class KeyService:
    """Generate and persist RSA key pairs as JSON files."""

    @staticmethod
    def save_public(
        key: RSAPublicKey,
        path: str | Path,
    ) -> Path:
        if not isinstance(key, RSAPublicKey):
            raise TypeError("key must be an RSAPublicKey")
        text = json.dumps(key.to_dict(), ensure_ascii=False, indent=2) + "\n"
        return atomic_write_text(path, text, mode=0o644)

    @staticmethod
    def load_public(path: str | Path) -> RSAPublicKey:
        data = _read_json_object(path)
        try:
            return RSAPublicKey.from_dict(data)
        except ValueError as exc:
            raise KeyFileError("public key file is invalid") from exc

    @staticmethod
    def save_private(
        key: RSAPrivateKey,
        path: str | Path,
        *,
        password: str | None = None,
    ) -> Path:
        if not isinstance(key, RSAPrivateKey):
            raise TypeError("key must be an RSAPrivateKey")

        payload = (
            _encrypt_private_key(key, password)
            if password is not None
            else key.to_dict()
        )
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        return atomic_write_text(path, text, mode=0o600)

    @staticmethod
    def load_private(
        path: str | Path,
        *,
        password: str | None = None,
    ) -> RSAPrivateKey:
        data = _read_json_object(path)
        if data.get("format") == ENCRYPTED_PRIVATE_FORMAT:
            return _decrypt_private_key(data, password)

        try:
            return RSAPrivateKey.from_dict(data)
        except ValueError as exc:
            raise KeyFileError("private key file is invalid") from exc

    @staticmethod
    def generate(
        name: str,
        *,
        bits: int = 2048,
        keys_dir: str | Path = "keys",
        password: str | None = None,
    ) -> GeneratedKey:
        key_name = validate_key_name(name)
        directory = Path(keys_dir)
        directory.mkdir(parents=True, exist_ok=True)

        private_key = generate_keypair(bits=bits)
        private_path = directory / f"{key_name}_private.json"
        public_path = directory / f"{key_name}_public.json"

        KeyService.save_private(private_key, private_path, password=password)
        KeyService.save_public(private_key.public_key, public_path)

        return GeneratedKey(
            private_key=private_key,
            private_path=private_path,
            public_path=public_path,
        )
