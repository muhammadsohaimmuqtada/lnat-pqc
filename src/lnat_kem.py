"""Archived LNAT KEM-v1 experiment (cryptographically broken).

KEM-v1 masks an encoded secret with the public trace Y. Because Y is public,
any observer can remove that mask and recover the same session key. Retained
only for reproducible negative testing. Instantiation requires allow_broken=True.
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


@dataclass(frozen=True)
class PrivateKey:
    seed: bytes
    params: LNATParams


@dataclass(frozen=True)
class Ciphertext:
    ct_bits: list[int]


def _validate_bits(bits: list[int], name: str) -> None:
    if not isinstance(bits, list) or any(bit not in (0, 1) for bit in bits):
        raise ValueError(f"{name} must be a list of bits")


def bits_to_bytes(bits: list[int]) -> bytes:
    _validate_bits(bits, "bits")
    padded = bits + [0] * ((-len(bits)) % 8)
    out = bytearray()
    for offset in range(0, len(padded), 8):
        byte = 0
        for bit in padded[offset : offset + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


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
    if repeat <= 0 or repeat % 2 == 0 or len(bits) % repeat:
        raise ValueError("invalid repetition encoding")
    return [1 if sum(bits[i : i + repeat]) > repeat // 2 else 0 for i in range(0, len(bits), repeat)]


def H(data: bytes, length: int = 32) -> bytes:
    return hashlib.shake_256(b"LNAT-KEM-V1-BROKEN|KDF|" + data).digest(length)


def _extend_trace(trace: list[int], length: int) -> list[int]:
    _validate_bits(trace, "trace")
    if not trace:
        raise ValueError("trace must not be empty")
    return (trace * ((length + len(trace) - 1) // len(trace)))[:length]


class BrokenLNATKEMV1:
    REPEAT = IMPLEMENTED_REPETITION_FACTOR

    def __init__(self, params: LNATParams = LNAT128, *, allow_broken: bool = False):
        if not allow_broken:
            raise RuntimeError(BROKEN_SECURITY_NOTICE)
        self.params = params

    def keygen(self, *, noise_rng=None):
        seed = generate_seed(self.params)
        sk = PrivateKey(seed, self.params)
        automaton = LNATAutomaton(seed, self.params)
        nonce = secrets.token_bytes(16)
        q0 = automaton.derive_q0(nonce)
        seed_A, inputs = generate_input_sequence(self.params)
        Y = automaton.run_noisy(q0, inputs, rng=noise_rng)
        return PublicKey(seed_A, nonce, Y, self.params), sk

    def encap(self, pk: PublicKey):
        r_bits = [secrets.randbits(1) for _ in range(self.params.kappa)]
        encoded = encode_with_repetition(r_bits, self.REPEAT)
        ct = Ciphertext(xor_bits(encoded, _extend_trace(pk.Y, len(encoded))))
        return ct, H(bits_to_bytes(r_bits))

    def decap(self, sk: PrivateKey, pk: PublicKey, ct: Ciphertext):
        automaton = LNATAutomaton(sk.seed, self.params)
        q0 = automaton.derive_q0(pk.nonce)
        _, inputs = generate_input_sequence(self.params, pk.seed_A)
        clean = automaton.run_noiseless(q0, inputs)
        recovered = xor_bits(ct.ct_bits, _extend_trace(clean, len(ct.ct_bits)))
        r_bits = decode_with_repetition(recovered, self.REPEAT)[: self.params.kappa]
        return H(bits_to_bytes(r_bits))


def recover_session_key_from_public_data(pk: PublicKey, ct: Ciphertext, *, repeat: int = 7):
    encoded = xor_bits(ct.ct_bits, _extend_trace(pk.Y, len(ct.ct_bits)))
    r_bits = decode_with_repetition(encoded, repeat)[: pk.params.kappa]
    return H(bits_to_bytes(r_bits))


LNATKEM = BrokenLNATKEMV1
