"""Prime generation and Miller-Rabin primality testing.

The implementation follows the probabilistic test presented in the course:
for a candidate ``n`` we write ``n - 1 = 2^s * d`` and test random bases.
A candidate that survives 40 rounds is accepted; the error probability is
below 2**-80.
"""

from __future__ import annotations

import secrets

from .numtheory import gcd, modexp

# Trial division by small primes removes most composites before the expensive
# Miller-Rabin rounds.  The sieve is computed once at import time.
def _sieve(limit: int = 2000) -> tuple[int, ...]:
    flags = bytearray(b"\x01") * (limit + 1)
    flags[0:2] = b"\x00\x00"
    for number in range(2, int(limit**0.5) + 1):
        if flags[number]:
            start = number * number
            flags[start : limit + 1 : number] = b"\x00" * (
                (limit - start) // number + 1
            )
    return tuple(index for index, flag in enumerate(flags) if flag)


_SMALL_PRIMES = _sieve()


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Return ``True`` if ``n`` passes a Miller-Rabin probable-prime test."""

    if rounds < 1:
        raise ValueError("rounds must be at least 1")
    if n < 2:
        return False

    for prime in _SMALL_PRIMES:
        if n % prime == 0:
            return n == prime

    # n > 2000 and odd here.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        base = 2 + secrets.randbelow(n - 3)  # 2 <= base <= n - 2
        value = modexp(base, d, n)
        if value == 1 or value == n - 1:
            continue

        for _ in range(s - 1):
            value = (value * value) % n
            if value == n - 1:
                break
        else:
            # No value of n - 1 was reached: n is composite.
            return False

    return True


def generate_prime(bits: int, e: int | None = None, rounds: int = 40) -> int:
    """Generate a random probable prime with exactly ``bits`` bits.

    When ``e`` is provided, the candidate is constrained to ``gcd(p - 1, e) == 1``
    so that it can be used directly for RSA key generation.
    """

    if bits < 16:
        raise ValueError("bits must be at least 16")
    if e is not None and (e < 3 or e % 2 == 0):
        raise ValueError("e must be an odd integer greater than 1")

    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if e is not None and gcd(candidate - 1, e) != 1:
            continue
        if is_probable_prime(candidate, rounds=rounds):
            return candidate
