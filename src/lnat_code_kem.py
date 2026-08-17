"""LNAT-CODE-KEM-0: complete research KeyGen/Encap/Decap harness.

This module completes the *mechanics* of a KEM-like construction around
LNAT-CODE-BRIDGE-0. It does not create a new security assumption:

* public-key asymmetry remains the random-code noisy-decoding relation;
* LNAT derives the receiver's sparse decoding witness;
* a random encapsulated seed is encrypted bit-by-bit with the public code;
* a confirmation tag detects decoding/tampering failures; and
* the final 32-byte session key is extracted with SHAKE256.

There is no IND-CCA proof, the reference ciphertext is intentionally large,
and the code-based parameters are research parameters only. The production-
usable path in this repository remains the ML-KEM-backed hybrid.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from code_pke_reference import (
    CodePKECiphertext,
    CodePKEParams,
    decrypt_bit as code_decrypt_bit,
    public_dual_basis,
    random_linear_combination,
    sparse_vector,
)
from lnat_code_bridge import (
    ByteBitRNG,
    LNATCodeBridgeParams,
    LNATCodeBridgePublicKey,
    LNATCodeBridgeSecretKey,
    keygen as bridge_keygen,
    recover_code_secret,
)
from lnat_params import LNAT128

KEM_VERSION = "LNAT-CODE-KEM-0"

DEFAULT_KEM_BRIDGE = LNATCodeBridgeParams(
    code=CodePKEParams(
        n=128,
        k=64,
        secret_weight=4,
        encryption_error_weight=1,
        repetitions=128,
        zero_threshold=0.25,
    ),
    lnat=LNAT128,
)


@dataclass(frozen=True)
class LNATCodeKEMParams:
    bridge: LNATCodeBridgeParams = DEFAULT_KEM_BRIDGE
    encapsulated_seed_bytes: int = 16
    confirmation_tag_bytes: int = 16

    def __post_init__(self) -> None:
        if self.encapsulated_seed_bytes <= 0:
            raise ValueError("encapsulated_seed_bytes must be positive")
        if not 8 <= self.confirmation_tag_bytes <= 64:
            raise ValueError("confirmation_tag_bytes must be in [8, 64]")

    @property
    def encapsulated_seed_bits(self) -> int:
        return self.encapsulated_seed_bytes * 8


@dataclass(frozen=True)
class LNATCodeKEMCiphertext:
    bit_ciphertexts: tuple[CodePKECiphertext, ...]
    confirmation_tag: bytes
    params: LNATCodeKEMParams

    def __post_init__(self) -> None:
        if len(self.bit_ciphertexts) != self.params.encapsulated_seed_bits:
            raise ValueError("ciphertext bit count does not match encapsulated seed size")
        if len(self.confirmation_tag) != self.params.confirmation_tag_bytes:
            raise ValueError("confirmation tag length mismatch")
        if any(ct.params != self.params.bridge.code for ct in self.bit_ciphertexts):
            raise ValueError("code ciphertext parameter mismatch")

    def size_bytes(self) -> int:
        return len(_ciphertext_body(self)) + len(self.confirmation_tag)


def _rng(rng: ByteBitRNG | None) -> ByteBitRNG:
    return secrets.SystemRandom() if rng is None else rng


def _random_bytes(source: ByteBitRNG, length: int) -> bytes:
    return bytes(source.getrandbits(8) for _ in range(length))


def _bytes_to_bits(data: bytes) -> tuple[int, ...]:
    return tuple((byte >> shift) & 1 for byte in data for shift in range(7, -1, -1))


def _bits_to_bytes(bits: tuple[int, ...]) -> bytes:
    if len(bits) % 8 != 0 or any(bit not in (0, 1) for bit in bits):
        raise ValueError("bits must be a byte-aligned bit tuple")
    out = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset : offset + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def _public_context(pk: LNATCodeBridgePublicKey, params: LNATCodeKEMParams) -> bytes:
    code = params.bridge.code
    word_bytes = (code.n + 7) // 8
    header = struct.pack(
        ">IIIIII",
        code.n,
        code.k,
        code.secret_weight,
        code.encryption_error_weight,
        code.repetitions,
        params.encapsulated_seed_bytes,
    )
    threshold = struct.pack(">d", code.zero_threshold)
    generator = b"".join(row.to_bytes(word_bytes, "big") for row in pk.code_key.generator)
    noisy = pk.code_key.noisy_codeword.to_bytes(word_bytes, "big")
    return (
        KEM_VERSION.encode("ascii")
        + b"|PUBLIC|"
        + header
        + threshold
        + generator
        + noisy
        + pk.nonce
        + pk.input_seed
    )


def _ciphertext_body(ct: LNATCodeKEMCiphertext) -> bytes:
    code = ct.params.bridge.code
    word_bytes = (code.n + 7) // 8
    return b"".join(
        word.to_bytes(word_bytes, "big")
        for bit_ct in ct.bit_ciphertexts
        for word in bit_ct.words
    )


def _confirmation_tag(
    seed_material: bytes,
    public_digest: bytes,
    body: bytes,
    tag_bytes: int,
) -> bytes:
    return hashlib.shake_256(
        KEM_VERSION.encode("ascii")
        + b"|CONFIRM|"
        + seed_material
        + public_digest
        + body
    ).digest(tag_bytes)


def _session_key(
    seed_material: bytes,
    public_digest: bytes,
    body: bytes,
    tag: bytes,
) -> bytes:
    return hashlib.shake_256(
        KEM_VERSION.encode("ascii")
        + b"|KDF|"
        + seed_material
        + public_digest
        + body
        + tag
    ).digest(32)


def _encrypt_bits_public(
    pk: LNATCodeBridgePublicKey,
    bits: tuple[int, ...],
    *,
    rng: ByteBitRNG,
) -> tuple[CodePKECiphertext, ...]:
    """Encrypt bits with one cached public dual basis."""
    code = pk.params.code
    dual = public_dual_basis(pk.code_key)
    encrypted: list[CodePKECiphertext] = []
    for bit in bits:
        if bit == 1:
            words = tuple(rng.getrandbits(code.n) for _ in range(code.repetitions))
        elif bit == 0:
            values = []
            for _ in range(code.repetitions):
                dual_word = random_linear_combination(dual, rng=rng)
                error = sparse_vector(code.n, code.encryption_error_weight, rng=rng)
                values.append(dual_word ^ error)
            words = tuple(values)
        else:
            raise ValueError("bits must contain only 0 or 1")
        encrypted.append(CodePKECiphertext(words, code))
    return tuple(encrypted)


class LNATCodeKEM0:
    """Complete research KEM mechanics over LNAT-CODE-BRIDGE-0."""

    def __init__(self, params: LNATCodeKEMParams = LNATCodeKEMParams()) -> None:
        self.params = params

    def keygen(
        self,
        *,
        rng: ByteBitRNG | None = None,
    ) -> tuple[LNATCodeBridgePublicKey, LNATCodeBridgeSecretKey]:
        return bridge_keygen(self.params.bridge, rng=rng)

    def encap(
        self,
        pk: LNATCodeBridgePublicKey,
        *,
        rng: ByteBitRNG | None = None,
    ) -> tuple[LNATCodeKEMCiphertext, bytes]:
        if pk.params != self.params.bridge:
            raise ValueError("public-key parameter mismatch")
        source = _rng(rng)
        seed_material = _random_bytes(source, self.params.encapsulated_seed_bytes)
        bit_ciphertexts = _encrypt_bits_public(
            pk,
            _bytes_to_bits(seed_material),
            rng=source,
        )
        placeholder = LNATCodeKEMCiphertext(
            bit_ciphertexts,
            b"\x00" * self.params.confirmation_tag_bytes,
            self.params,
        )
        body = _ciphertext_body(placeholder)
        public_digest = hashlib.sha256(_public_context(pk, self.params)).digest()
        tag = _confirmation_tag(
            seed_material,
            public_digest,
            body,
            self.params.confirmation_tag_bytes,
        )
        ct = LNATCodeKEMCiphertext(bit_ciphertexts, tag, self.params)
        return ct, _session_key(seed_material, public_digest, body, tag)

    def decap(
        self,
        sk: LNATCodeBridgeSecretKey,
        pk: LNATCodeBridgePublicKey,
        ct: LNATCodeKEMCiphertext,
    ) -> bytes:
        if sk.params != self.params.bridge or pk.params != self.params.bridge:
            raise ValueError("key parameter mismatch")
        if ct.params != self.params:
            raise ValueError("ciphertext parameter mismatch")

        code_secret = recover_code_secret(sk, pk)
        bits = tuple(code_decrypt_bit(code_secret, bit_ct) for bit_ct in ct.bit_ciphertexts)
        seed_material = _bits_to_bytes(bits)
        body = _ciphertext_body(ct)
        public_digest = hashlib.sha256(_public_context(pk, self.params)).digest()
        expected_tag = _confirmation_tag(
            seed_material,
            public_digest,
            body,
            self.params.confirmation_tag_bytes,
        )
        if not hmac.compare_digest(expected_tag, ct.confirmation_tag):
            raise ValueError("ciphertext confirmation failed")
        return _session_key(
            seed_material,
            public_digest,
            body,
            ct.confirmation_tag,
        )


if __name__ == "__main__":
    kem = LNATCodeKEM0()
    pk, sk = kem.keygen()
    ct, sender = kem.encap(pk)
    receiver = kem.decap(sk, pk, ct)
    print(f"profile={KEM_VERSION}")
    print(f"encapsulated-seed-bits={kem.params.encapsulated_seed_bits}")
    print(f"ciphertext-bytes={ct.size_bytes()}")
    print(f"shared-key-bytes={len(sender)}")
    print(f"round-trip={sender == receiver}")
    print("security-boundary=random-code decoding; no IND-CCA or standalone-LNAT claim")
