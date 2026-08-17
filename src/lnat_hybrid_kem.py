"""Operational research KEM: ML-KEM-768 with LNAT-EXP2 post-processing.

This module provides a *working* PQC KEM interface while keeping the security
boundary explicit:

* ML-KEM-768 supplies the public-key encapsulation primitive.
* LNAT-EXP2 is a deterministic, secret-seeded post-processing transform.
* The final KDF includes the raw ML-KEM shared secret directly, so LNAT is not
  treated as an independent source of entropy or security.

This construction is a research integration profile, not a new standardized
KEM and not a proof that standalone LNAT is secure.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol

from lnat_core import LNATAutomaton, bits_to_bytes, generate_input_sequence
from lnat_params import LNAT128, LNATParams

PROFILE = b"LNAT-MLKEM768-HYBRID-v1"
KEY_BYTES = 32
CONTEXT_SEED_BYTES = 32
MLKEM768_PUBLIC_BYTES = 1184
MLKEM768_PRIVATE_SEED_BYTES = 64
MLKEM768_CIPHERTEXT_BYTES = 1088
MLKEM768_SHARED_SECRET_BYTES = 32

PK_MAGIC = b"LNHK-P1"
SK_MAGIC = b"LNHK-S1"
CT_MAGIC = b"LNHK-C1"


class MLKEM768Backend(Protocol):
    def generate(self) -> tuple[bytes, bytes]: ...
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]: ...
    def decapsulate(self, private_seed: bytes, ciphertext: bytes) -> bytes: ...
    def public_from_private_seed(self, private_seed: bytes) -> bytes: ...


class CryptographyMLKEM768Backend:
    """ML-KEM-768 backend using pyca/cryptography >= 47."""

    @staticmethod
    def _imports():
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.mlkem import (
                MLKEM768PrivateKey,
                MLKEM768PublicKey,
            )
        except ImportError as exc:
            raise RuntimeError(
                "ML-KEM support requires cryptography>=47. Install with "
                "`python -m pip install -e '.[pqc]'`."
            ) from exc
        return serialization, MLKEM768PrivateKey, MLKEM768PublicKey

    def generate(self) -> tuple[bytes, bytes]:
        serialization, PrivateKey, _ = self._imports()
        private = PrivateKey.generate()
        public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        seed = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _validate_len("ML-KEM public key", public, MLKEM768_PUBLIC_BYTES)
        _validate_len("ML-KEM private seed", seed, MLKEM768_PRIVATE_SEED_BYTES)
        return public, seed

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        _, _, PublicKey = self._imports()
        _validate_len("ML-KEM public key", public_key, MLKEM768_PUBLIC_BYTES)
        shared_secret, ciphertext = PublicKey.from_public_bytes(public_key).encapsulate()
        _validate_len("ML-KEM shared secret", shared_secret, MLKEM768_SHARED_SECRET_BYTES)
        _validate_len("ML-KEM ciphertext", ciphertext, MLKEM768_CIPHERTEXT_BYTES)
        return shared_secret, ciphertext

    def decapsulate(self, private_seed: bytes, ciphertext: bytes) -> bytes:
        _, PrivateKey, _ = self._imports()
        _validate_len("ML-KEM private seed", private_seed, MLKEM768_PRIVATE_SEED_BYTES)
        _validate_len("ML-KEM ciphertext", ciphertext, MLKEM768_CIPHERTEXT_BYTES)
        shared_secret = PrivateKey.from_seed_bytes(private_seed).decapsulate(ciphertext)
        _validate_len("ML-KEM shared secret", shared_secret, MLKEM768_SHARED_SECRET_BYTES)
        return shared_secret

    def public_from_private_seed(self, private_seed: bytes) -> bytes:
        serialization, PrivateKey, _ = self._imports()
        _validate_len("ML-KEM private seed", private_seed, MLKEM768_PRIVATE_SEED_BYTES)
        public = PrivateKey.from_seed_bytes(private_seed).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        _validate_len("ML-KEM public key", public, MLKEM768_PUBLIC_BYTES)
        return public


def _validate_len(name: str, value: bytes, expected: int) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes")


def _profile_name_bytes(params: LNATParams) -> bytes:
    encoded = params.name.encode("ascii")
    if len(encoded) > 255:
        raise ValueError("profile name is too long")
    return encoded


def _encode_profile(params: LNATParams) -> bytes:
    name = _profile_name_bytes(params)
    return bytes([len(name)]) + name


def _decode_profile(data: bytes, offset: int = 0) -> tuple[str, int]:
    if offset >= len(data):
        raise ValueError("missing profile length")
    length = data[offset]
    offset += 1
    end = offset + length
    if end > len(data):
        raise ValueError("truncated profile name")
    try:
        return data[offset:end].decode("ascii"), end
    except UnicodeDecodeError as exc:
        raise ValueError("profile name must be ASCII") from exc


def _require_profile(name: str, params: LNATParams) -> None:
    if name != params.name:
        raise ValueError(f"profile mismatch: encoded={name!r}, expected={params.name!r}")


@dataclass(frozen=True)
class HybridPublicKey:
    mlkem_public: bytes
    context_seed: bytes
    params: LNATParams = LNAT128

    def __post_init__(self) -> None:
        _validate_len("ML-KEM public key", self.mlkem_public, MLKEM768_PUBLIC_BYTES)
        _validate_len("context_seed", self.context_seed, CONTEXT_SEED_BYTES)

    def to_bytes(self) -> bytes:
        return PK_MAGIC + _encode_profile(self.params) + self.context_seed + self.mlkem_public

    @classmethod
    def from_bytes(cls, data: bytes, params: LNATParams = LNAT128) -> "HybridPublicKey":
        if not isinstance(data, bytes) or not data.startswith(PK_MAGIC):
            raise ValueError("invalid hybrid public-key magic")
        name, offset = _decode_profile(data, len(PK_MAGIC))
        _require_profile(name, params)
        expected = offset + CONTEXT_SEED_BYTES + MLKEM768_PUBLIC_BYTES
        if len(data) != expected:
            raise ValueError("invalid hybrid public-key length")
        context = data[offset : offset + CONTEXT_SEED_BYTES]
        public = data[offset + CONTEXT_SEED_BYTES :]
        return cls(public, context, params)


@dataclass(frozen=True)
class HybridPrivateKey:
    mlkem_private_seed: bytes
    context_seed: bytes
    params: LNATParams = LNAT128

    def __post_init__(self) -> None:
        _validate_len("ML-KEM private seed", self.mlkem_private_seed, MLKEM768_PRIVATE_SEED_BYTES)
        _validate_len("context_seed", self.context_seed, CONTEXT_SEED_BYTES)

    def to_bytes(self) -> bytes:
        return SK_MAGIC + _encode_profile(self.params) + self.context_seed + self.mlkem_private_seed

    @classmethod
    def from_bytes(cls, data: bytes, params: LNATParams = LNAT128) -> "HybridPrivateKey":
        if not isinstance(data, bytes) or not data.startswith(SK_MAGIC):
            raise ValueError("invalid hybrid private-key magic")
        name, offset = _decode_profile(data, len(SK_MAGIC))
        _require_profile(name, params)
        expected = offset + CONTEXT_SEED_BYTES + MLKEM768_PRIVATE_SEED_BYTES
        if len(data) != expected:
            raise ValueError("invalid hybrid private-key length")
        context = data[offset : offset + CONTEXT_SEED_BYTES]
        seed = data[offset + CONTEXT_SEED_BYTES :]
        return cls(seed, context, params)


@dataclass(frozen=True)
class HybridCiphertext:
    mlkem_ciphertext: bytes
    public_context_tag: bytes

    def __post_init__(self) -> None:
        _validate_len("ML-KEM ciphertext", self.mlkem_ciphertext, MLKEM768_CIPHERTEXT_BYTES)
        _validate_len("public context tag", self.public_context_tag, 16)

    def to_bytes(self) -> bytes:
        return CT_MAGIC + self.public_context_tag + self.mlkem_ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridCiphertext":
        if not isinstance(data, bytes) or not data.startswith(CT_MAGIC):
            raise ValueError("invalid hybrid ciphertext magic")
        expected = len(CT_MAGIC) + 16 + MLKEM768_CIPHERTEXT_BYTES
        if len(data) != expected:
            raise ValueError("invalid hybrid ciphertext length")
        offset = len(CT_MAGIC)
        return cls(data[offset + 16 :], data[offset : offset + 16])


def public_key_digest(pk: HybridPublicKey) -> bytes:
    return hashlib.sha3_256(b"LNAT-HYBRID|PK-DIGEST|" + pk.to_bytes()).digest()


def public_context_tag(pk: HybridPublicKey) -> bytes:
    return hashlib.sha3_256(b"LNAT-HYBRID|PUBLIC-CONTEXT|" + pk.to_bytes()).digest()[:16]


def derive_hybrid_key(mlkem_shared_secret: bytes, pk: HybridPublicKey, mlkem_ciphertext: bytes) -> bytes:
    _validate_len("ML-KEM shared secret", mlkem_shared_secret, MLKEM768_SHARED_SECRET_BYTES)
    _validate_len("ML-KEM ciphertext", mlkem_ciphertext, MLKEM768_CIPHERTEXT_BYTES)
    pk_hash = public_key_digest(pk)
    lnat_seed = hashlib.shake_256(
        PROFILE + b"|LNAT-SEED|" + mlkem_shared_secret + pk_hash + mlkem_ciphertext
    ).digest(pk.params.seed_size)
    nonce = hashlib.shake_256(PROFILE + b"|NONCE|" + pk_hash + mlkem_ciphertext).digest(16)
    input_seed = hashlib.shake_256(PROFILE + b"|INPUT-SEED|" + pk_hash + mlkem_ciphertext).digest(32)
    automaton = LNATAutomaton(lnat_seed, pk.params)
    q0 = automaton.derive_q0(nonce)
    _, inputs = generate_input_sequence(pk.params, input_seed)
    transcript = bits_to_bytes(automaton.run_noiseless(q0, inputs))
    return hashlib.shake_256(
        PROFILE + b"|FINAL|" + mlkem_shared_secret + pk_hash + mlkem_ciphertext + transcript
    ).digest(KEY_BYTES)


class LNATMLKEM768:
    """Operational ML-KEM-768 + LNAT-EXP2 research integration profile."""

    def __init__(self, params: LNATParams = LNAT128, *, backend: MLKEM768Backend | None = None) -> None:
        self.params = params
        self.backend = backend if backend is not None else CryptographyMLKEM768Backend()

    def keygen(self) -> tuple[HybridPublicKey, HybridPrivateKey]:
        public, private_seed = self.backend.generate()
        context_seed = secrets.token_bytes(CONTEXT_SEED_BYTES)
        return HybridPublicKey(public, context_seed, self.params), HybridPrivateKey(private_seed, context_seed, self.params)

    def encap(self, pk: HybridPublicKey) -> tuple[HybridCiphertext, bytes]:
        if pk.params != self.params:
            raise ValueError("public-key parameter mismatch")
        shared, mlkem_ct = self.backend.encapsulate(pk.mlkem_public)
        ct = HybridCiphertext(mlkem_ct, public_context_tag(pk))
        return ct, derive_hybrid_key(shared, pk, mlkem_ct)

    def decap(self, sk: HybridPrivateKey, pk: HybridPublicKey, ct: HybridCiphertext) -> bytes:
        if sk.params != self.params or pk.params != self.params:
            raise ValueError("parameter mismatch")
        if not hmac.compare_digest(sk.context_seed, pk.context_seed):
            raise ValueError("private/public context mismatch")
        expected_public = self.backend.public_from_private_seed(sk.mlkem_private_seed)
        if not hmac.compare_digest(expected_public, pk.mlkem_public):
            raise ValueError("private key does not match public key")
        if not hmac.compare_digest(ct.public_context_tag, public_context_tag(pk)):
            raise ValueError("ciphertext is bound to a different public context")
        shared = self.backend.decapsulate(sk.mlkem_private_seed, ct.mlkem_ciphertext)
        return derive_hybrid_key(shared, pk, ct.mlkem_ciphertext)


if __name__ == "__main__":
    kem = LNATMLKEM768()
    pk, sk = kem.keygen()
    ct, sender = kem.encap(pk)
    receiver = kem.decap(sk, pk, ct)
    print(f"profile={PROFILE.decode()}")
    print(f"public-key-bytes={len(pk.to_bytes())}")
    print(f"ciphertext-bytes={len(ct.to_bytes())}")
    print(f"shared-key-bytes={len(sender)}")
    print(f"round-trip={sender == receiver}")
    print("security-boundary=ML-KEM-768; LNAT remains experimental")
