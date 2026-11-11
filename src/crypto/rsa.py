"""RSA key generation and raw signature primitives.

Scope of this phase (P1)
------------------------
This module implements the mathematical core of RSA:

* key generation with 1024-bit primes and ``e = 65537``;
* raw private-key operation ``s = m^d mod n`` (with CRT acceleration);
* raw public-key operation ``m = s^e mod n``.

It deliberately does **not** define the document signing format yet.  Hashing
and EMSA-PKCS1-v1_5 padding are added in phase P2; until then, ``sign_int`` and
``verify_int`` must only be used on an already-padded representative, never on
a bare document hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import cast

from .encoding import int_to_bytes
from .numtheory import gcd, lcm, modexp, modinv
from .primes import generate_prime

_PUBLIC_FORMAT = "RSA-PUB/1"
_PRIVATE_FORMAT = "RSA-PRIV/1"


def _validate_public_exponent(e: int) -> None:
    if e < 3 or e % 2 == 0:
        raise ValueError("public exponent e must be an odd integer >= 3")


@dataclass(frozen=True, slots=True)
class RSAPublicKey:
    """RSA public key ``(n, e)``."""

    n: int
    e: int

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise ValueError("modulus n must be positive")
        _validate_public_exponent(self.e)
        if self.e >= self.n:
            raise ValueError("public exponent e must be smaller than n")

    @property
    def key_size(self) -> int:
        """Modulus size in bits."""

        return self.n.bit_length()

    def canonical_bytes(self) -> bytes:
        """Deterministic encoding used for fingerprints and key comparison."""

        n_bytes = int_to_bytes(self.n)
        e_bytes = int_to_bytes(self.e)
        return (
            b"RSA-PUB/1\x00"
            + len(n_bytes).to_bytes(4, "big")
            + n_bytes
            + len(e_bytes).to_bytes(4, "big")
            + e_bytes
        )

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the canonical public-key encoding."""

        digest = hashlib.sha256(self.canonical_bytes()).hexdigest()
        return f"sha256:{digest}"

    def apply(self, value: int) -> int:
        """Raw public-key operation ``value^e mod n``."""

        if not 0 <= value < self.n:
            raise ValueError("value must satisfy 0 <= value < n")
        return modexp(value, self.e, self.n)

    def verify_int(self, message: int, signature: int) -> bool:
        """Return ``True`` when ``signature^e mod n == message``."""

        if not 0 <= message < self.n:
            return False
        try:
            recovered = self.apply(signature)
        except ValueError:
            return False
        return recovered == message

    def to_dict(self) -> dict[str, str | int]:
        return {
            "format": _PUBLIC_FORMAT,
            "n": str(self.n),
            "e": self.e,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "RSAPublicKey":
        if data.get("format") != _PUBLIC_FORMAT:
            raise ValueError(f"unsupported public key format: {data.get('format')!r}")
        try:
            key = cls(n=int(str(data["n"])), e=int(str(data["e"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed public key") from exc

        recorded = data.get("fingerprint")
        if recorded is not None and recorded != key.fingerprint:
            raise ValueError("public key fingerprint does not match its contents")
        return key


@dataclass(frozen=True, slots=True)
class RSAPrivateKey:
    """RSA private key with CRT parameters.

    ``dp``, ``dq`` and ``qinv`` are optional in the constructor and computed
    automatically when omitted.  The object is immutable and its ``repr`` never
    exposes secret values.
    """

    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int | None = field(default=None, repr=False)
    dq: int | None = field(default=None, repr=False)
    qinv: int | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.p <= 1 or self.q <= 1:
            raise ValueError("p and q must be greater than 1")
        if self.p == self.q:
            raise ValueError("p and q must be distinct")
        if self.p * self.q != self.n:
            raise ValueError("n must equal p * q")
        if self.d <= 0:
            raise ValueError("private exponent d must be positive")
        _validate_public_exponent(self.e)

        lambda_n = lcm(self.p - 1, self.q - 1)
        if gcd(self.e, lambda_n) != 1:
            raise ValueError("e is not coprime with lcm(p - 1, q - 1)")
        if (self.e * self.d) % lambda_n != 1:
            raise ValueError("d is not the inverse of e modulo lcm(p - 1, q - 1)")

        dp = self.d % (self.p - 1)
        dq = self.d % (self.q - 1)
        qinv = modinv(self.q, self.p)

        if self.dp is not None and self.dp != dp:
            raise ValueError("inconsistent CRT exponent dp")
        if self.dq is not None and self.dq != dq:
            raise ValueError("inconsistent CRT exponent dq")
        if self.qinv is not None and self.qinv != qinv:
            raise ValueError("inconsistent CRT coefficient qinv")

        object.__setattr__(self, "dp", dp)
        object.__setattr__(self, "dq", dq)
        object.__setattr__(self, "qinv", qinv)

    def __repr__(self) -> str:
        return (
            f"RSAPrivateKey(bits={self.n.bit_length()}, "
            f"fingerprint={self.public_key.fingerprint!r})"
        )

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    def sign_int(self, message: int) -> int:
        """Raw private-key operation ``message^d mod n`` using CRT.

        ``message`` is the padded encoded message (EM), not a document hash.
        """

        if not 0 <= message < self.n:
            raise ValueError("message must satisfy 0 <= message < n")

        m1 = modexp(message % self.p, cast(int, self.dp), self.p)
        m2 = modexp(message % self.q, cast(int, self.dq), self.q)
        h = (cast(int, self.qinv) * (m1 - m2)) % self.p
        return m2 + h * self.q

    def recover_int(self, signature: int) -> int:
        """Raw public-key operation used to verify a signature."""

        return self.public_key.apply(signature)

    def to_dict(self) -> dict[str, str | int]:
        return {
            "format": _PRIVATE_FORMAT,
            "n": str(self.n),
            "e": self.e,
            "d": str(self.d),
            "p": str(self.p),
            "q": str(self.q),
            "dp": str(self.dp),
            "dq": str(self.dq),
            "qinv": str(self.qinv),
            "public_fingerprint": self.public_key.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "RSAPrivateKey":
        if data.get("format") != _PRIVATE_FORMAT:
            raise ValueError(f"unsupported private key format: {data.get('format')!r}")
        try:
            key = cls(
                n=int(str(data["n"])),
                e=int(str(data["e"])),
                d=int(str(data["d"])),
                p=int(str(data["p"])),
                q=int(str(data["q"])),
                dp=int(str(data["dp"])) if data.get("dp") is not None else None,
                dq=int(str(data["dq"])) if data.get("dq") is not None else None,
                qinv=int(str(data["qinv"])) if data.get("qinv") is not None else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed private key") from exc

        recorded = data.get("public_fingerprint")
        if recorded is not None and recorded != key.public_key.fingerprint:
            raise ValueError("private key does not match its public fingerprint")
        return key


def generate_keypair(
    bits: int = 2048,
    e: int = 65537,
    rounds: int = 40,
) -> RSAPrivateKey:
    """Generate an RSA key pair with a modulus of exactly ``bits`` bits.

    The default 2048-bit size matches the requirement in the pre-project
    report.  ``rounds`` is exposed for tests; production use should keep the
    default of 40 Miller-Rabin rounds.
    """

    if bits < 256:
        raise ValueError("bits must be at least 256")
    _validate_public_exponent(e)

    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits, e=e, rounds=rounds)
        q = generate_prime(q_bits, e=e, rounds=rounds)
        if p == q:
            continue
        if p < q:
            # Keep p > q, the conventional layout expected by PKCS#1 tooling.
            p, q = q, p

        n = p * q
        if n.bit_length() != bits:
            continue

        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue

        d = modinv(e, phi)
        if d <= 1:
            continue

        return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q)


__all__ = [
    "RSAPublicKey",
    "RSAPrivateKey",
    "generate_keypair",
]
