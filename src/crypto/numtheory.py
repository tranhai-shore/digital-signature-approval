"""Number-theoretic helpers used by the RSA core.

All functions are intentionally implemented with plain Python integers so the
project stays self-contained and the algorithms from the course labs remain
visible (square-and-multiply, extended Euclid, modular inverse).
"""

from __future__ import annotations

from math import gcd as _math_gcd


def modexp(base: int, exponent: int, modulus: int) -> int:
    """Return ``base ** exponent mod modulus`` using square-and-multiply.

    This mirrors the algorithm from Lab 2 and is used instead of the built-in
    ``pow`` to keep the cryptographic primitive explicit and testable.
    """

    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    base %= modulus
    result = 1 % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: return ``(g, x, y)`` with ``a*x + b*y == g == gcd(a, b)``."""

    if a == 0 and b == 0:
        return (0, 0, 0)

    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if old_r < 0:
        old_r, old_s, old_t = -old_r, -old_s, -old_t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int) -> int:
    """Return the multiplicative inverse of ``a`` modulo ``modulus``.

    Raises ``ValueError`` when the inverse does not exist.
    """

    if modulus <= 0:
        raise ValueError("modulus must be positive")

    g, x, _ = egcd(a % modulus, modulus)
    if g != 1:
        raise ValueError(f"{a} and {modulus} are not coprime; inverse does not exist")
    return x % modulus


def gcd(a: int, b: int) -> int:
    """Return the non-negative greatest common divisor of ``a`` and ``b``."""

    return _math_gcd(a, b)


def lcm(a: int, b: int) -> int:
    """Return the least common multiple of ``a`` and ``b``."""

    if a == 0 or b == 0:
        return 0
    return abs(a // _math_gcd(a, b) * b)


def are_coprime(a: int, b: int) -> bool:
    """Return ``True`` when ``gcd(a, b) == 1``."""

    return _math_gcd(a, b) == 1
