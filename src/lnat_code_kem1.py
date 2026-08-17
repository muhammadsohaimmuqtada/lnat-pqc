"""LNAT-CODE-KEM-1: segmented outer-code research KEM harness.

KEM-1 keeps the same explicit random-code security boundary as KEM-0 but
replaces per-bit repetition with 8-bit outer-code blocks. Each byte is decoded
with a 256-message ML search, so a 128-bit encapsulated seed becomes 16 small
problems instead of one infeasible 2^128 search.

This is still research-only: the outer code is random, the decoder is not a
scalable production decoder, there is no IND-CCA proof, and public code
syndrome decoding remains the attack target. The operational PQC path remains
LNAT-MLKEM768-HYBRID-v1.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from code_pke_reference import BitRNG
from code_segmented_outer import (
    SegmentedOuterCiphertext,
    SegmentedOuterCode,
    decrypt_segmented_message,
    encrypt_segmented_message,
    generate_segmented_outer_code,
)
from lnat_code_bridge import (
    LNATCodeBridgeParams,
    LNATCodeBridgePublicKey,
    LNATCodeBridgeSecretKey,
    keygen as bridge_keygen,
    recover_code_secret,
)
from lnat_code_kem import DEFAULT_KEM_BRIDGE

KEM1_VERSION = "LNAT-CODE-KEM-1"


@dataclass(frozen=True)
class LNATCodeKEM1Params:
    bridge: LNATCodeBridgeParams = DEFAULT_KEM_BRIDGE
    encapsulated_seed_bytes: int = 16
    channel_uses_per_byte: int = 128
    confirmation_tag_bytes: int = 16

    def __post_init__(self) -> None:
        if self.encapsulated_seed_bytes <= 0:
            raise ValueError("encapsulated_seed_bytes must be positive")
        if self.channel_uses_per_byte <= 8:
            raise ValueError("channel_uses_per_byte must exceed 8")
        if not 8 <= self.confirmation_tag_bytes <= 64:
            raise ValueError("confirmation_tag_bytes must be in [8, 64]")

    @property
    def encapsulated_seed_bits(self) -> int:
        return self.encapsulated_seed_bytes * 8


@dataclass(frozen=True)
class LNATCodeKEM1PublicKey:
    bridge_key: LNATCodeBridgePublicKey
    outer_code: SegmentedOuterCode
    params: LNATCodeKEM1Params

    def __post_init__(self) -> None:
        if self.bridge_key.params != self.params.bridge:
            raise ValueError("bridge public-key parameter mismatch")
        if self.outer_code.message_bytes != self.params.encapsulated_seed_bytes:
            raise ValueError("outer-code block count mismatch")
        if self.outer_code.channel_uses_per_byte != self.params.channel_uses_per_byte:
            raise ValueError("outer-code channel length mismatch")


@dataclass(frozen=True)
class LNATCodeKEM1Ciphertext:
    payload: SegmentedOuterCiphertext
    confirmation_tag: bytes
    params: LNATCodeKEM1Params

    def __post_init__(self) -> None:
        if self.payload.params != self.params.bridge.code:
            raise ValueError("ciphertext code parameter mismatch")
        if self.payload.message_bytes != self.params.encapsulated_seed_bytes:
            raise ValueError("ciphertext block count mismatch")
        if len(self.confirmation_tag) != self.params.confirmation_tag_bytes:
            raise ValueError("confirmation tag length mismatch")

    def size_bytes(self) -> int:
        return self.payload.size_bytes() + len(self.confirmation_tag)


def _rng(rng: BitRNG | None) -> BitRNG:
    return secrets.SystemRandom() if rng is None else rng


def _random_bytes(source: BitRNG, length: int) -> bytes:
    return bytes(source.getrandbits(8) for _ in range(length))


def _public_context(pk: LNATCodeKEM1PublicKey) -> bytes:
    params = pk.params
    code = params.bridge.code
    word_bytes = (code.n + 7) // 8
    header = struct.pack(
        ">IIIIIII",
        code.n,
        code.k,
        code.secret_weight,
        code.encryption_error_weight,
        params.encapsulated_seed_bytes,
        params.channel_uses_per_byte,
        params.confirmation_tag_bytes,
    )
    threshold = struct.pack(">d", code.zero_threshold)
    generator = b"".join(
        row.to_bytes(word_bytes, "big") for row in pk.bridge_key.code_key.generator
    )
    noisy = pk.bridge_key.code_key.noisy_codeword.to_bytes(word_bytes, "big")
    outer_bytes = (params.channel_uses_per_byte + 7) // 8
    outer = b"".join(
        row.to_bytes(outer_bytes, "big")
        for block in pk.outer_code.blocks
        for row in block.generator_rows
    )
    return (
        KEM1_VERSION.encode("ascii")
        + b"|PUBLIC|"
        + header
        + threshold
        + generator
        + noisy
        + pk.bridge_key.nonce
        + pk.bridge_key.input_seed
        + outer
    )


def _ciphertext_body(ct: LNATCodeKEM1Ciphertext) -> bytes:
    word_bytes = (ct.params.bridge.code.n + 7) // 8
    return b"".join(
        word.to_bytes(word_bytes, "big")
        for block in ct.payload.blocks
        for word in block.words
    )


def _confirmation_tag(
    seed_material: bytes,
    public_digest: bytes,
    body: bytes,
    tag_bytes: int,
) -> bytes:
    return hashlib.shake_256(
        KEM1_VERSION.encode("ascii")
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
        KEM1_VERSION.encode("ascii")
        + b"|KDF|"
        + seed_material
        + public_digest
        + body
        + tag
    ).digest(32)


class LNATCodeKEM1:
    """Functional segmented research KEM with bytewise ML outer decoding."""

    def __init__(self, params: LNATCodeKEM1Params = LNATCodeKEM1Params()) -> None:
        self.params = params

    def keygen(
        self,
        *,
        rng: BitRNG | None = None,
    ) -> tuple[LNATCodeKEM1PublicKey, LNATCodeBridgeSecretKey]:
        source = _rng(rng)
        bridge_pk, bridge_sk = bridge_keygen(self.params.bridge, rng=source)
        outer = generate_segmented_outer_code(
            self.params.encapsulated_seed_bytes,
            self.params.channel_uses_per_byte,
            rng=source,
        )
        return LNATCodeKEM1PublicKey(bridge_pk, outer, self.params), bridge_sk

    def encap(
        self,
        pk: LNATCodeKEM1PublicKey,
        *,
        rng: BitRNG | None = None,
    ) -> tuple[LNATCodeKEM1Ciphertext, bytes]:
        if pk.params != self.params:
            raise ValueError("public-key parameter mismatch")
        source = _rng(rng)
        seed_material = _random_bytes(source, self.params.encapsulated_seed_bytes)
        payload = encrypt_segmented_message(
            pk.bridge_key.code_key,
            pk.outer_code,
            seed_material,
            rng=source,
        )
        placeholder = LNATCodeKEM1Ciphertext(
            payload,
            b"\x00" * self.params.confirmation_tag_bytes,
            self.params,
        )
        body = _ciphertext_body(placeholder)
        public_digest = hashlib.sha256(_public_context(pk)).digest()
        tag = _confirmation_tag(
            seed_material,
            public_digest,
            body,
            self.params.confirmation_tag_bytes,
        )
        ct = LNATCodeKEM1Ciphertext(payload, tag, self.params)
        return ct, _session_key(seed_material, public_digest, body, tag)

    def decap(
        self,
        sk: LNATCodeBridgeSecretKey,
        pk: LNATCodeKEM1PublicKey,
        ct: LNATCodeKEM1Ciphertext,
    ) -> bytes:
        if sk.params != self.params.bridge or pk.params != self.params:
            raise ValueError("key parameter mismatch")
        if ct.params != self.params:
            raise ValueError("ciphertext parameter mismatch")

        code_secret = recover_code_secret(sk, pk.bridge_key)
        seed_material = decrypt_segmented_message(
            code_secret,
            ct.payload,
            pk.outer_code,
        )
        body = _ciphertext_body(ct)
        public_digest = hashlib.sha256(_public_context(pk)).digest()
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
    kem = LNATCodeKEM1()
    pk, sk = kem.keygen()
    ct, sender = kem.encap(pk)
    receiver = kem.decap(sk, pk, ct)
    repetition_reference_bytes = (
        kem.params.encapsulated_seed_bits
        * kem.params.bridge.code.repetitions
        * ((kem.params.bridge.code.n + 7) // 8)
        + kem.params.confirmation_tag_bytes
    )
    print(f"profile={KEM1_VERSION}")
    print(f"encapsulated-seed-bits={kem.params.encapsulated_seed_bits}")
    print(f"channel-uses-per-byte={kem.params.channel_uses_per_byte}")
    print(f"total-channel-uses={pk.outer_code.total_channel_uses}")
    print(f"ciphertext-bytes={ct.size_bytes()}")
    print(f"kem0-repetition-reference-bytes={repetition_reference_bytes}")
    print(f"size-reduction={repetition_reference_bytes / ct.size_bytes():.6f}x")
    print(f"round-trip={sender == receiver}")
    print("security-boundary=random-code decoding; research-only, no standalone LNAT or IND-CCA claim")
