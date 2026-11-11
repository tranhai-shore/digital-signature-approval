"""Unit tests for the number-theoretic helpers."""

from __future__ import annotations

import pytest

from src.crypto.numtheory import (
    are_coprime,
    egcd,
    gcd,
    lcm,
    modexp,
    modinv,
)


@pytest.mark.parametrize(
    ("base", "exponent", "modulus"),
    [
        (2, 10, 1000),
        (3, 0, 7),
        (0, 5, 13),
        (123, 456, 789),
        (85625, 625, 7),
        (65537, 12345, 2**61 - 1),
    ],
)
def test_modexp_matches_builtin_pow(base: int, exponent: int, modulus: int) -> None:
    assert modexp(base, exponent, modulus) == pow(base, exponent, modulus)


def test_modexp_handles_modulus_one() -> None:
    assert modexp(123, 0, 1) == 0
    assert modexp(123, 456, 1) == 0


def test_modexp_rejects_invalid_arguments() -> None:
    with pytest.raises(ValueError):
        modexp(2, 3, 0)
    with pytest.raises(ValueError):
        modexp(2, -1, 7)


@pytest.mark.parametrize(
    ("a", "b"),
    [(240, 46), (0, 5), (-12, 18), (12, -18), (-12, -18), (2**64, 3**40)],
)
def test_egcd_returns_bezout_identity(a: int, b: int) -> None:
    g, x, y = egcd(a, b)
    assert g == gcd(a, b)
    assert a * x + b * y == g


def test_modinv_matches_python_inverse() -> None:
    # Lab 2, exercise 4: inverse of 65537 modulo 35256.
    inverse = modinv(65537, 35256)
    assert (65537 * inverse) % 35256 == 1
    assert inverse == pow(65537, -1, 35256)


def test_modinv_raises_when_not_coprime() -> None:
    with pytest.raises(ValueError):
        modinv(6, 9)


def test_modinv_normalises_negative_input() -> None:
    assert (modinv(-3, 11) * -3) % 11 == 1


def test_gcd_and_lcm() -> None:
    assert gcd(240, 46) == 2
    assert lcm(4, 6) == 12
    assert lcm(0, 5) == 0
    assert are_coprime(9, 28)
    assert not are_coprime(9, 27)
