"""Cryptographic helpers compatible with the Rust ZINCHA primitives."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from typing import Dict, Optional, Protocol, Union

ADDRESS_PREFIX = "zn1"

BytesLike = Union[bytes, bytearray, memoryview]

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _Q - 2, _Q) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


class SignedRequestSigner(Protocol):
    def address(self) -> str:
        ...

    def public_key_hex(self) -> str:
        ...

    def sign(self, message: bytes) -> bytes:
        ...


def strip_hex_prefix(value: str) -> str:
    return value[2:] if value.startswith(("0x", "0X")) else value


def bytes_to_hex(value: BytesLike) -> str:
    return bytes(value).hex()


def hex_to_bytes(value: str, expected_length: Optional[int] = None) -> bytes:
    normalized = strip_hex_prefix(value).strip()
    if len(normalized) % 2 != 0:
        raise ValueError("invalid hex string")
    try:
        out = bytes.fromhex(normalized)
    except ValueError as error:
        raise ValueError("invalid hex string") from error
    if expected_length is not None and len(out) != expected_length:
        raise ValueError("expected %d bytes, got %d" % (expected_length, len(out)))
    return out


def sha256(value: Union[BytesLike, str]) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hashlib.sha256(data).digest()


def sha256_hex(value: Union[BytesLike, str]) -> str:
    return sha256(value).hex()


def raw_address_hex(address: str) -> str:
    value = address.strip().lower()
    raw = value[len(ADDRESS_PREFIX):] if value.startswith(ADDRESS_PREFIX) else value
    if len(raw) != 40:
        raise ValueError("invalid ZINCHA address: %s" % address)
    try:
        bytes.fromhex(raw)
    except ValueError as error:
        raise ValueError("invalid ZINCHA address: %s" % address) from error
    return raw


def normalize_address(address: str) -> str:
    return ADDRESS_PREFIX + raw_address_hex(address)


def address_from_public_key(public_key: BytesLike) -> str:
    public_key_bytes = bytes(public_key)
    if len(public_key_bytes) != 32:
        raise ValueError("public key must be 32 bytes, got %d" % len(public_key_bytes))
    return ADDRESS_PREFIX + sha256(public_key_bytes)[12:32].hex()


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _edwards(point: tuple, other: tuple) -> tuple:
    x1, y1 = point
    x2, y2 = other
    denominator = pow(1 + _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    x3 = (x1 * y2 + x2 * y1) * denominator % _Q
    denominator = pow(1 - _D * x1 * x2 * y1 * y2, _Q - 2, _Q)
    y3 = (y1 * y2 + x1 * x2) * denominator % _Q
    return x3, y3


def _scalarmult(point: tuple, scalar: int) -> tuple:
    if scalar == 0:
        return 0, 1
    half = _scalarmult(point, scalar // 2)
    doubled = _edwards(half, half)
    if scalar & 1:
        return _edwards(doubled, point)
    return doubled


def _encode_point(point: tuple) -> bytes:
    x, y = point
    value = y | ((x & 1) << 255)
    return value.to_bytes(32, "little")


def _decode_point(encoded: bytes) -> tuple:
    if len(encoded) != 32:
        raise ValueError("encoded point must be 32 bytes")
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    sign = encoded[31] >> 7
    if y >= _Q:
        raise ValueError("invalid Ed25519 point")
    xx = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = x * _I % _Q
    if (x * x - xx) % _Q != 0:
        raise ValueError("invalid Ed25519 point")
    if (x & 1) != sign:
        x = _Q - x
    return x, y


def _clamped_scalar(seed: bytes) -> tuple:
    digest = _sha512(seed)
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return int.from_bytes(scalar, "little"), digest[32:]


def ed25519_public_key_from_seed(seed: BytesLike) -> bytes:
    seed_bytes = bytes(seed)
    if len(seed_bytes) != 32:
        raise ValueError("secret key must be 32 bytes, got %d" % len(seed_bytes))
    scalar, _ = _clamped_scalar(seed_bytes)
    return _encode_point(_scalarmult(_B, scalar))


def ed25519_sign(seed: BytesLike, message: BytesLike) -> bytes:
    seed_bytes = bytes(seed)
    message_bytes = bytes(message)
    if len(seed_bytes) != 32:
        raise ValueError("secret key must be 32 bytes, got %d" % len(seed_bytes))
    scalar, prefix = _clamped_scalar(seed_bytes)
    public_key = ed25519_public_key_from_seed(seed_bytes)
    r = int.from_bytes(_sha512(prefix + message_bytes), "little") % _L
    encoded_r = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(encoded_r + public_key + message_bytes), "little") % _L
    s = (r + k * scalar) % _L
    return encoded_r + s.to_bytes(32, "little")


def ed25519_verify(public_key: BytesLike, message: BytesLike, signature: BytesLike) -> bool:
    public_key_bytes = bytes(public_key)
    message_bytes = bytes(message)
    signature_bytes = bytes(signature)
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        return False
    try:
        r_point = _decode_point(signature_bytes[:32])
        a_point = _decode_point(public_key_bytes)
    except ValueError:
        return False
    s = int.from_bytes(signature_bytes[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(
        _sha512(signature_bytes[:32] + public_key_bytes + message_bytes),
        "little",
    ) % _L
    return _scalarmult(_B, s) == _edwards(r_point, _scalarmult(a_point, k))


class Keypair:
    def __init__(self, secret: BytesLike) -> None:
        secret_bytes = bytes(secret)
        if len(secret_bytes) != 32:
            raise ValueError("secret key must be 32 bytes, got %d" % len(secret_bytes))
        self._secret = secret_bytes
        self._public_key = ed25519_public_key_from_seed(secret_bytes)
        self._address = address_from_public_key(self._public_key)

    @classmethod
    def generate(cls) -> "Keypair":
        return cls(os.urandom(32))

    @classmethod
    def from_secret_bytes(cls, secret: BytesLike) -> "Keypair":
        return cls(secret)

    @classmethod
    def from_secret_hex(cls, secret_hex: str) -> "Keypair":
        return cls(hex_to_bytes(secret_hex, 32))

    def secret_bytes(self) -> bytes:
        return self._secret

    def secret_hex(self) -> str:
        return self._secret.hex()

    def public_key(self) -> bytes:
        return self._public_key

    def public_key_hex(self) -> str:
        return self._public_key.hex()

    def address(self) -> str:
        return self._address

    def sign(self, message: BytesLike) -> bytes:
        return ed25519_sign(self._secret, bytes(message))

    def verify(self, message: BytesLike, signature: BytesLike) -> bool:
        return ed25519_verify(self._public_key, bytes(message), bytes(signature))


def signed_request_headers(
    signer: SignedRequestSigner,
    method: str,
    request_target: str,
    body: Optional[Union[BytesLike, str]] = None,
    nonce: Optional[str] = None,
    timestamp_ms: Optional[int] = None,
) -> Dict[str, str]:
    if body is None:
        body_bytes = b""
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = bytes(body)

    timestamp = int(timestamp_ms if timestamp_ms is not None else time.time() * 1000)
    request_nonce = nonce if nonce is not None else secrets.token_hex(16)
    body_hash = sha256_hex(body_bytes)
    public_key = signer.public_key_hex()
    message = "\n".join(
        [
            "zincha-rpc-signed-request-v1",
            method.upper(),
            request_target,
            str(timestamp),
            request_nonce,
            body_hash,
            signer.address(),
            public_key,
        ]
    ).encode("utf-8")

    return {
        "x-zincha-address": signer.address(),
        "x-zincha-public-key": public_key,
        "x-zincha-signature": signer.sign(message).hex(),
        "x-zincha-timestamp-ms": str(timestamp),
        "x-zincha-nonce": request_nonce,
        "x-zincha-body-sha256": body_hash,
    }
