"""Crypto core package for the digital-signature document approval project."""

from .encoding import (
    b64url_decode,
    b64url_encode,
    bytes_to_int,
    constant_time_compare,
    int_to_bytes,
)
from .hashing import (
    DEFAULT_CHUNK_SIZE,
    SHA256_DIGEST_SIZE,
    sha256_bytes,
    sha256_file,
    sha256_stream,
)
from .numtheory import are_coprime, egcd, gcd, lcm, modexp, modinv
from .padding import (
    MIN_EM_LENGTH,
    SHA256_DIGEST_INFO,
    PaddingError,
    decode_pkcs1_v1_5,
    encode_pkcs1_v1_5,
)
from .primes import generate_prime, is_probable_prime
from .rsa import RSAPrivateKey, RSAPublicKey, generate_keypair
from .signature import (
    SignatureFormatError,
    recover_digest,
    sign_bytes,
    sign_digest,
    sign_file,
    verify_bytes,
    verify_digest,
    verify_file,
)

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "MIN_EM_LENGTH",
    "PaddingError",
    "RSAPrivateKey",
    "RSAPublicKey",
    "SHA256_DIGEST_INFO",
    "SHA256_DIGEST_SIZE",
    "SignatureFormatError",
    "are_coprime",
    "b64url_decode",
    "b64url_encode",
    "bytes_to_int",
    "constant_time_compare",
    "decode_pkcs1_v1_5",
    "egcd",
    "encode_pkcs1_v1_5",
    "gcd",
    "generate_keypair",
    "generate_prime",
    "int_to_bytes",
    "is_probable_prime",
    "lcm",
    "modexp",
    "modinv",
    "recover_digest",
    "sha256_bytes",
    "sha256_file",
    "sha256_stream",
    "sign_bytes",
    "sign_digest",
    "sign_file",
    "verify_bytes",
    "verify_digest",
    "verify_file",
]
