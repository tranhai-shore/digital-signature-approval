"""Unit tests for Miller-Rabin primality testing and prime generation."""

from __future__ import annotations

import pytest

from src.crypto.numtheory import gcd
from src.crypto.primes import generate_prime, is_probable_prime


@pytest.mark.parametrize("candidate", [2, 3, 5, 7, 97, 7919, 104729, 2**127 - 1])
def test_known_primes_are_accepted(candidate: int) -> None:
    assert is_probable_prime(candidate, rounds=40)


@pytest.mark.parametrize(
    "candidate",
    [1, 0, -7, 4, 9, 15, 21, 25, 49, 561, 1105, 1729, 2047, 10403],
)
def test_known_composites_are_rejected(candidate: int) -> None:
    assert not is_probable_prime(candidate, rounds=40)


def test_rounds_must_be_positive() -> None:
    with pytest.raises(ValueError):
        is_probable_prime(17, rounds=0)


def test_generate_prime_has_requested_size_and_is_prime() -> None:
    prime = generate_prime(64, e=65537, rounds=32)
    assert prime.bit_length() == 64
    assert prime % 2 == 1
    assert is_probable_prime(prime, rounds=32)
    assert gcd(prime - 1, 65537) == 1


def test_generate_prime_respects_small_public_exponent() -> None:
    prime = generate_prime(32, e=3, rounds=24)
    assert prime.bit_length() == 32
    assert gcd(prime - 1, 3) == 1


def test_generate_prime_rejects_invalid_arguments() -> None:
    with pytest.raises(ValueError):
        generate_prime(8)
    with pytest.raises(ValueError):
        generate_prime(64, e=4)
