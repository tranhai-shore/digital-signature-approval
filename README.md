# DSIG

**Metadata-bound document signatures with RSA-2048, SHA-256 and PKCS#1 v1.5.**

DSIG is a self-contained Python implementation of a digital document approval workflow. A signer produces a detached `.sig` package that binds the document bytes to the signer identity, original filename, file size and signing time. A verifier can then check the document and every signed metadata field using only the signer's public key.

The cryptographic core — modular arithmetic, prime generation, RSA key generation, CRT, SHA-256 streaming, EMSA-PKCS1-v1_5 encoding and signature verification — is implemented with the Python standard library. Password-protected key storage and interoperability tests optionally use the `cryptography` package.

## Design goals

- **Integrity** — any change to the document is detected by SHA-256.
- **Authenticity** — the signature can only be produced with the private key.
- **Metadata binding** — signer, filename, size and timestamp are covered by the signature, not stored as unsigned hints.
- **Deterministic verification** — every failure maps to a stable, machine-readable reason code.
- **Auditability** — the complete signing and verification path is implemented in readable Python.
- **Safe file handling** — keys and packages are written atomically; private keys use restrictive permissions.

## Features

- RSA-2048 key generation with `e = 65537`, Miller-Rabin primality testing and CRT-accelerated signing.
- Streaming SHA-256 hashing (1 MiB chunks) so large documents are never loaded fully into memory.
- EMSA-PKCS1-v1_5 encoding/decoding with strict validation of the full encoded message.
- Canonical TBS (*to-be-signed*) construction with a domain separator and length prefixes.
- UTF-8 JSON `.sig` packages with schema validation and Unicode NFC normalization.
- Strict JSON policy for packages and key files: 1 MiB size cap, duplicate-key rejection, and rejection of `NaN`/`Infinity`.
- Detached signature verification with 14 stable reason codes.
- Optional password-protected private keys using PBKDF2-HMAC-SHA256 and AES-256-GCM.
- Command-line interface for key generation, signing, verification, inspection and tamper demos, with JSON output and deterministic exit codes.
- Tkinter desktop application with key management, signing, verification banners and a tamper-demo workflow.
- Byte-for-byte interoperability tests against the `cryptography` package (optional).

## Architecture

```text
digital-signature-approval/
├── src/
│   ├── cli.py                     # dsig command-line interface
│   ├── gui/
│   │   ├── app.py                 # Tkinter tabs, background tasks, result banners
│   │   └── support.py             # display formatting and input validation
│   ├── crypto/
│   │   ├── numtheory.py           # modular exponentiation, egcd, modinv, gcd/lcm
│   │   ├── primes.py              # Miller-Rabin and prime generation
│   │   ├── rsa.py                 # key generation, raw RSA, CRT, fingerprints
│   │   ├── hashing.py             # streaming SHA-256
│   │   ├── padding.py             # strict EMSA-PKCS1-v1_5
│   │   ├── signature.py           # safe document signing and verification
│   │   └── encoding.py            # int/bytes, base64url, constant-time compare
│   ├── models/
│   │   ├── signature_package.py   # .sig schema and metadata validation
│   │   ├── json_support.py        # strict JSON limits, duplicates, non-finite
│   │   ├── timestamp.py           # canonical UTC timestamps
│   │   └── verification.py        # reason codes, messages and results
│   └── services/
│       ├── tbs.py                 # canonical TBS builder
│       ├── sign_service.py        # sign files or in-memory data
│       ├── verify_service.py      # verify documents and classify failures
│       ├── package_service.py     # read/write .sig JSON
│       ├── key_service.py         # key generation and storage
│       └── file_service.py        # atomic writes and default paths
├── tests/
│   ├── test_numtheory.py
│   ├── test_primes.py
│   ├── test_rsa.py
│   ├── test_hashing.py
│   ├── test_padding.py
│   ├── test_signature.py
│   ├── test_encoding.py
│   ├── test_tbs.py
│   ├── test_package.py
│   ├── test_key_service.py
│   ├── test_sign_verify_service.py
│   ├── test_file_service.py
│   ├── test_gui.py
│   ├── test_hardening.py
│   └── test_cli.py
└── docs/
    ├── SIGNATURE_FORMAT.md        # TBS, package and key format specification
    ├── KE_HOACH_TRIEN_KHAI.md     # internal implementation plan
    └── pre_project_report.md      # background and requirements analysis
```

## Cryptographic design

### Key generation

- Modulus size: **2048 bits** by default; `e = 65537`.
- Prime candidates are tested with Miller-Rabin using **40 rounds**.
- The private exponent is computed as `d = e⁻¹ mod φ(N)`; CRT parameters `dp`, `dq` and `qinv` are derived and validated.
- Every signature is checked against the public key immediately after generation to catch CRT faults.
- Public-key fingerprint:

```text
SHA-256("RSA-PUB/1" || len(n) || n || len(e) || e)
```

### Signed payload (TBS)

The signature does not cover the JSON text directly. It covers a canonical byte string rebuilt from the package metadata:

```text
TBS = b"DSIGv1\x00"
   || u32(len(algorithm))      || algorithm
   || u32(len(signer))         || signer
   || u32(len(original_name))  || original_name
   || u64(size)
   || u32(len(signed_at))      || signed_at
   || SHA-256(document)        # 32 raw bytes
```

All integers are big-endian and all strings are UTF-8. The design provides:

- **Domain separation** — `DSIGv1\0` prevents a TBS from being confused with signed data from another protocol.
- **Unambiguous parsing** — every variable-length field is length-prefixed, so `("ab", "c")` and `("a", "bc")` produce different TBS values.
- **Canonical metadata** — signer and filename are normalized to Unicode NFC; timestamps must include an offset and are converted to UTC `YYYY-MM-DDTHH:MM:SSZ`; filenames must be basenames.
- **Stable signing time** — timestamps are truncated to second precision before signing.

### Signature encoding

The TBS is hashed with SHA-256 and encoded as an EMSA-PKCS1-v1_5 `DigestInfo` structure:

```text
EM = 0x00 || 0x01 || 0xFF...FF || 0x00 || DigestInfo(SHA-256) || SHA-256(TBS)
```

Padding is decoded strictly: header, padding string, separator and DigestInfo must all match. Signatures always have the same length as the modulus — 256 bytes for RSA-2048.

### Package format

A `.sig` file is UTF-8 JSON:

```json
{
  "format": "DSIG/1",
  "algorithm": "RSA-PKCS1v15-SHA256",
  "signer": "Alice",
  "key_fingerprint": "sha256:…",
  "file": {
    "original_name": "contract.pdf",
    "size": 1234,
    "sha256": "…"
  },
  "signed_at": "2026-11-11T10:00:00Z",
  "signature": "…base64url…"
}
```

Packages contain no private key material. The full schema, key formats and compatibility rules are specified in [`docs/SIGNATURE_FORMAT.md`](docs/SIGNATURE_FORMAT.md).

### Verification pipeline

Verification runs in a fixed order so that the earliest possible cause is reported:

1. Parse and validate the package.
2. Check the expected signer, when supplied.
3. Compare the public-key fingerprint with the package.
4. Confirm the document exists and is readable.
5. Compare the document size.
6. Compute SHA-256 over the document.
7. Rebuild the TBS and verify the RSA signature and padding.
8. Report `VALID`.

| Reason | Meaning |
|---|---|
| `VALID` | Signature is valid; document and metadata are unchanged. |
| `PACKAGE_NOT_FOUND` | `.sig` file does not exist. |
| `PACKAGE_READ_ERROR` | Package cannot be read (directory, permission, I/O error). |
| `PACKAGE_MALFORMED` | Invalid JSON, UTF-8 or schema. |
| `UNSUPPORTED_ALGORITHM` | Package declares an unsupported signature algorithm. |
| `KEY_MISMATCH` | Public key does not match the package fingerprint. |
| `SIGNER_MISMATCH` | Signer differs from the expected identity. |
| `FILE_NOT_FOUND` | Document does not exist. |
| `FILE_READ_ERROR` | Document cannot be read. |
| `SIZE_MISMATCH` | Document size differs from signed metadata. |
| `HASH_MISMATCH` | Document content changed; SHA-256 differs. |
| `SIGNATURE_MALFORMED` | Signature has the wrong length/format or is out of range. |
| `PADDING_INVALID` | EMSA-PKCS1-v1_5 structure is invalid. |
| `TBS_MISMATCH` | Signature does not match the signed metadata. |

## Installation

Python **3.10 or newer** is required.

```bash
git clone https://github.com/tranhai-shore/digital-signature-approval.git
cd digital-signature-approval
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

For the optional interoperability tests and password-protected key support:

```bash
pip install -r requirements-dev.txt
```

## Command-line interface

Run the CLI as a module:

```bash
python -m src.cli --version
# equivalent
python -m src --version
```

### Generate a key pair

```bash
python -m src.cli keygen --name alice --bits 2048
```

```text
Generated RSA-2048 key 'alice'
Fingerprint: sha256:…
Private key: keys/alice_private.json
Public key:  keys/alice_public.json
Keep the private key secret; it is not encrypted.
```

Protect the private key with a password. Omitting the value prompts without echoing:

```bash
python -m src.cli keygen --name alice --password
python -m src.cli keygen --name alice --password-file .password
```

### Sign a document

```bash
python -m src.cli sign \
  --key keys/alice_private.json \
  --file contract.pdf \
  --signer "Alice"
```

The default output is `contract.pdf.sig`. Use `--out` to choose another path and `--signed-at` to override the timestamp (useful for reproducible demos and tests).

### Verify a document

```bash
python -m src.cli verify \
  --key keys/alice_public.json \
  --file contract.pdf \
  --sig contract.pdf.sig \
  --signer "Alice"
```

```text
VALID: contract.pdf
Signer: Alice
Signed at: 2026-11-11T10:00:00Z
Fingerprint: sha256:…
```

For automation, add `--json`:

```bash
python -m src.cli verify --key keys/alice_public.json \
  --file contract.pdf --sig contract.pdf.sig --json
```

### Inspect a package

```bash
python -m src.cli inspect --sig contract.pdf.sig
```

`inspect` parses and displays metadata without verifying the signature.

### Print a key fingerprint

```bash
python -m src.cli fingerprint --key keys/alice_public.json
```

### Demonstrate tampering

```bash
python -m src.cli tamper \
  --file contract.pdf \
  --out contract-tampered.pdf \
  --offset 120
```

The command flips one bit in a copy of the file and never overwrites the source. Verifying the modified copy produces `HASH_MISMATCH`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Command succeeded; signature is valid for `verify`. |
| `1` | Verification failed (invalid or malformed signature). |
| `2` | Usage, I/O, key or package error. |

`--json` produces machine-readable output for all commands. Verification failures are reported in JSON with exit code `1`; operational errors are printed to stderr with exit code `2`.

## Desktop application

Launch the Tkinter interface with:

```bash
python -m src.gui
```

The window provides four tabs:

- **Keys** — generate RSA key pairs, load existing public/private keys, copy the fingerprint, export keys and send the selected keys to the signing or verification tab.
- **Sign** — choose a private key and document, compute the SHA-256 preview, enter the signer identity, sign, and write a `.sig` package.
- **Verify** — select a public key, document and package; optional expected signer; a green/red banner shows the result with the reason code and signed metadata.
- **Tamper demo** — create a copy with one flipped bit, then verify it to observe `HASH_MISMATCH`.

Key generation, hashing, signing and verification run on a worker thread so the window remains responsive with large documents. Every completed operation is written to the activity log.

### Optional standalone executable

PyInstaller is not a project dependency, but it can bundle the Tkinter application for a machine without Python:

```bash
pip install pyinstaller
pyinstaller --noconfirm --clean --windowed --name DSIG --paths . src/gui/__main__.py
```

The result is `dist/DSIG/DSIG.exe` on Windows. Add `--onefile` for a single executable. PyInstaller must run on the target operating system; a Windows build does not run on Linux or macOS.

## Library API

```python
from src.services.key_service import KeyService
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

generated = KeyService.generate("alice", bits=2048, keys_dir="keys")

result = SignService.sign_file(
    generated.private_key,
    "contract.pdf",
    signer="Alice",
)

verification = VerifyService.verify_file(
    "contract.pdf",
    result.package_path,
    generated.private_key.public_key,
    expected_signer="Alice",
)

assert verification.valid
print(verification.reason.value)  # VALID
```

For in-memory data:

```python
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

package = SignService.sign_data(
    generated.private_key,
    b"approval amount: 1000 USD",
    "Alice",
    "approval.txt",
)

result = VerifyService.verify_data(
    b"approval amount: 9000 USD",
    package,
    generated.private_key.public_key,
)
assert result.reason.value == "HASH_MISMATCH"
```

## Security properties and limits

DSIG provides:

- **Integrity** of document bytes and signed metadata.
- **Message authentication** for anyone holding the signer's trusted public key.
- **Non-repudiation** to the extent that the private key remains under the signer's control.
- **Atomic persistence** of keys and packages, avoiding partially written files.
- **Restrictive private-key permissions** (`0o600`) and optional password encryption with PBKDF2-HMAC-SHA256 (200,000 iterations) and AES-256-GCM.

DSIG applies the following limits to untrusted metadata:

- `.sig` and key JSON files are capped at **1 MiB**; larger files are rejected before being parsed.
- Duplicate JSON keys, `NaN`, `Infinity` and `-Infinity` are rejected.
- JSON integers are capped at 4,096 decimal digits.
- Signer identifiers are limited to 256 characters and filenames to 255 characters.
- Timestamps are limited to 64 characters before canonicalization.
- Packages and keys must be valid UTF-8; lone Unicode surrogates are rejected.

DSIG does **not** provide:

- A public-key infrastructure, certificate authority, revocation or trust-on-first-use policy. Public keys must be distributed and authenticated out of band.
- Trusted timestamping. `signed_at` is the signer's claimed time, not a third-party attestation.
- Protection against a compromised signer device or private key.
- Side-channel hardening. The implementation is written for clarity and auditability, not for constant-time execution on shared hardware.
- A replacement for a vetted production crypto library. Use established libraries and formats such as CMS or PAdES when regulatory or interoperability requirements apply.

## Testing

```bash
python -m pytest -q
```

The suite contains **286 tests** covering:

- modular exponentiation, Bézout coefficients, modular inverses and Miller-Rabin vectors;
- the textbook RSA vector `p=61, q=53, e=17, d=2753, m=65 → s=588`;
- 1024-bit functional keys and 2048-bit default keys;
- CRT consistency, signature round-trips, tampered signatures and wrong keys;
- NIST SHA-256 vectors and streaming with multiple chunk sizes;
- strict padding acceptance and rejection;
- TBS determinism, metadata binding, Unicode normalization and length-prefix ambiguity;
- package schema validation and Unicode filenames;
- key persistence, permissions, encrypted private keys and wrong-password handling;
- end-to-end signing and verification for every reason code;
- CLI key generation, signing, verification, inspection, fingerprinting, tamper demos, JSON output and exit codes;
- CLI and GUI helpers for atomic writes, bit flipping, size formatting and input validation;
- the Tkinter application shell, key-context synchronization and success/failure banners;
- strict JSON handling: 1 MiB caps, duplicate keys, non-finite numbers, invalid UTF-8 and oversized packages;
- metadata length limits, Unicode edge cases, empty documents and a 50 MiB streaming round-trip;
- deterministic fuzzing of package JSON, random package bytes and mutated valid packages;
- byte-for-byte interoperability with OpenSSL through the optional `cryptography` package.

## Compatibility

- Python **3.10+**
- Core runtime: standard library only (`hashlib`, `secrets`, `hmac`, `json`, `argparse`).
- Desktop UI: Tkinter, bundled with CPython on Windows and macOS; on Linux install `python3-tk`.
- Optional: `cryptography>=42` for password-protected private keys and interoperability tests.

## Documentation

- [`docs/SIGNATURE_FORMAT.md`](docs/SIGNATURE_FORMAT.md) — TBS layout, `.sig` schema, key formats, verification order and reason codes.
- [`docs/report/DSIG_Project_Report.pdf`](docs/report/DSIG_Project_Report.pdf) — project report (PDF).
- [`docs/report/DSIG_Project_Report.docx`](docs/report/DSIG_Project_Report.docx) — editable report source.
- [`docs/pre_project_report.md`](docs/pre_project_report.md) — background, requirements and threat analysis.
- [`docs/KE_HOACH_TRIEN_KHAI.md`](docs/KE_HOACH_TRIEN_KHAI.md) — internal implementation plan.
