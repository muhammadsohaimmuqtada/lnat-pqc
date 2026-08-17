"""Archived LNAT KEM-v1 experiment.

SECURITY STATUS: BROKEN.

KEM-v1 masks an encoded secret with the public trace Y. Because Y is public,
any observer can remove that mask and recover the same session key. The code
is retained only so the break is reproducible and future designs can be
regression-tested against it.

Instantiation requires `allow_broken=True` to prevent accidental use.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from lnat_core import LNATAutomaton, generate_input_sequence, generate_seed
from lnat_params import IMPLEMENTED_REPETITION_FACTOR, LNAT128, LNATParams

BROKEN_SECURITY_NOTICE = (
    "LNAT KEM-v1 is cryptographically broken: its ciphertext can be "
    "decapsulated from public data. Use only for research reproduction."
)


@dataclass(frozen=True)
class PublicKey:
    seed_A: bytes
    nonce: bytes
    Y: list[int]
    params: LNATParams

    def to_bytes(self) -> bytes:
        y_bytes = bits_to_bytes(self.Y)
        return self.seed_A + self.nonce + len(y_bytes).to_bytes(4, "big") + y_bytes

    def size_bytes(self) -> int:
        return len(self.to_bytes())


@dataclass(frozen=True)
class PrivateKey:
    seed: bytes
    params: LNATParams

    def to_bytes(self) -> bytes:
        return self.seed

    def size_bytes(self) -> int:
        return len(self.seed)


@dataclass(frozen=True)
class Ciphertext:
    ct_bits: list[int]

    def to_bytes(self) -> bytes:
        return bits_to_bytes(self.ct_bits)

    def size_bytes(self) -> int:
        return len(self.to_bytes())


def _validate_bits(bits: list[int], name: str) -> None:
    if not isinstance(bits, list) or any(bit not in (0, 1) for bit in bits):
        raise ValueError(f"{name} must be a list of bits")


def bits_to_bytes(bits: list[int]) -> bytes:
    _validate_bits(bits, "bits")
    padded = bits + [0] * ((-len(bits)) % 8)
    result = bytearray()
    for index in range(0, len(padded), 8):
        byte = 0
        for bit in padded[index : index + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def bytes_to_bits(data: bytes, n_bits: int) -> list[int]:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if n_bits < 0 or n_bits > len(data) * 8:
        raise ValueError("n_bits is outside the encoded data length")
    bits: list[int] = []
    for byte in data:
        bits.extend((byte >> shift) & 1 for shift in range(7, -1, -1))
    return bits[:n_bits]


def xor_bits(a: list[int], b: list[int]) -> list[int]:
    _validate_bits(a, "a")
    _validate_bits(b, "b")
    if len(a) != len(b):
        raise ValueError("bit sequences must have equal length")
    return [x ^ y for x, y in zip(a, b)]


def encode_with_repetition(bits: list[int], repeat: int = 7) -> list[int]:
    _validate_bits(bits, "bits")
    if repeat <= 0 or repeat % 2 == 0:
        raise ValueError("repeat must be a positive odd integer")
    return [bit for bit in bits for _ in range(repeat)]


def decode_with_repetition(bits: list[int], repeat: int = 7) -> list[int]:
    _validate_bits(bits, "bits")
    if repeat <= 0 or repeat % 2 == 0:
        raise ValueError("repeat must be a positive odd integer")
    if len(bits) % repeat != 0:
        raise ValueError("encoded bit length must be divisible by repeat")
    return [
        1 if sum(bits[index : index + repeat]) > repeat // 2 else 0
        for index in range(0, len(bits), repeat)
    ]


def H(data: bytes, length: int = 32) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if length <= 0:
        raise ValueError("length must be positive")
    return hashlib.shake_256(b"LNAT-KEM-V1-BROKEN|KDF|" + data).digest(length)


class BrokenLNATKEMV1:
    """Historical KEM-v1 implementation preserved for cryptanalysis."""

    REPEAT = IMPLEMENTED_REPETITION_FACTOR

    def __init__(
        self,
        params: LNATParams = LNAT128,
        *,
        allow_broken: bool = False,
    ) -> None:
        if not allow_broken:
            raise RuntimeError(BROKEN_SECURITY_NOTICE)
        self.params = params

    def _assert_params_match(self, other: LNATParams, what: str) -> None:
        if other != self.params:
            raise ValueError(f"parameter mismatch for {what}")

    def _validate_public_key(self, pk: PublicKey) -> None:
        self._assert_params_match(pk.params, "public key")
        if len(pk.seed_A) != 32:
            raise ValueError("seed_A must be 32 bytes")
        if len(pk.nonce) != 16:
            raise ValueError("nonce must be 16 bytes")
        if len(pk.Y) != self.params.T:
            raise ValueError("public trace length mismatch")
        _validate_bits(pk.Y, "public trace")

    def _validate_private_key(self, sk: PrivateKey) -> None:
        self._assert_params_match(sk.params, "private key")
        if len(sk.seed) != self.params.seed_size:
            raise ValueError("invalid private key length")

    def _validate_ciphertext(self, ct: Ciphertext) -> None:
        expected = self.params.kappa * self.REPEAT
        if len(ct.ct_bits) != expected:
            raise ValueError("invalid ciphertext length")
        _validate_bits(ct.ct_bits, "ciphertext")

    def keygen(self, *, noise_rng=None) -> tuple[PublicKey, PrivateKey]:
        seed = generate_seed(self.params)
        sk = PrivateKey(seed=seed, params=self.params)
        automaton = LNATAutomaton(seed, self.params)
        nonce = secrets.token_bytes(16)
        q0 = automaton.derive_q0(nonce)
        seed_A, inputs = generate_input_sequence(self.params)
        Y = automaton.run_noisy(q0, inputs, rng=noise_rng)
        return PublicKey(seed_A=seed_A, nonce=nonce, Y=Y, params=self.params), sk

    def encap(self, pk: PublicKey) -> tuple[Ciphertext, bytes]:
        self._validate_public_key(pk)
        r_bits = [secrets.randbits(1) for _ in range(self.params.kappa)]
        encoded = encode_with_repetition(r_bits, self.REPEAT)
        public_mask = _extend_trace(pk.Y, len(encoded))
        ct = Ciphertext(xor_bits(encoded, public_mask))
        return ct, H(bits_to_bytes(r_bits))

    def decap(self, sk: PrivateKey, pk: PublicKey, ct: Ciphertext) -> bytes:
        self._validate_private_key(sk)
        self._validate_public_key(pk)
        self._validate_ciphertext(ct)
        automaton = LNATAutomaton(sk.seed, self.params)
        q0 = automaton.derive_q0(pk.nonce)
        _, inputs = generate_input_sequence(self.params, seed_A=pk.seed_A)
        clean_trace = automaton.run_noiseless(q0, inputs)
        clean_mask = _extend_trace(clean_trace, len(ct.ct_bits))
        noisy_encoded = xor_bits(ct.ct_bits, clean_mask)
        r_bits = decode_with_repetition(noisy_encoded, self.REPEAT)[: self.params.kappa]
        return H(bits_to_bytes(r_bits))


def _extend_trace(trace: list[int], length: int) -> list[int]:
    _validate_bits(trace, "trace")
    if not trace:
        raise ValueError("trace must not be empty")
    if length < 0:
        raise ValueError("length must be non-negative")
    repeats = (length + len(trace) - 1) // len(trace)
    return (trace * repeats)[:length]


def recover_session_key_from_public_data(
    pk: PublicKey,
    ct: Ciphertext,
    *,
    repeat: int = IMPLEMENTED_REPETITION_FACTOR,
) -> bytes:
    """Reproduce the complete public-data attack against KEM-v1."""
    public_mask = _extend_trace(pk.Y, len(ct.ct_bits))
    encoded = xor_bits(ct.ct_bits, public_mask)
    r_bits = decode_with_repetition(encoded, repeat)[: pk.params.kappa]
    return H(bits_to_bytes(r_bits))


# Compatibility name is intentionally gated by the constructor.
LNATKEM = BrokenLNATKEMV1


if __name__ == "__main__":
    print(BROKEN_SECURITY_NOTICE)
    print("See attacks/public_recovery_v1.py and docs/KNOWN_BREAKS.md.")
