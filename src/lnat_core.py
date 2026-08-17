"""Reference implementation of the LNAT experimental primitive.

LNAT-EXP2 is a research object, not a standalone public-key cryptosystem:

    q_0 = Q0_s(nonce)
    q_t = Delta_s(q_{t-1}, a_t)
    z_t = Lambda_s(q_t, t)
    y_t = z_t XOR e_t

Delta, Q0, and Lambda are domain-separated HMAC-SHA256-derived functions.
The keyed observation function in EXP2 replaces the coordinate projection used
by EXP1 so the observed bit is not simply a fixed state bit. No hardness or
security claim follows from this change; it only removes an avoidable structural
leak from the research primitive.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Iterable

from lnat_params import LNAT128, LNATParams


def _require_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _domain(params: LNATParams, purpose: bytes) -> bytes:
    return params.domain_id + b"|" + purpose + b"|"


def prf(seed: bytes, domain: bytes, length: int) -> bytes:
    _require_bytes("seed", seed)
    _require_bytes("domain", domain)
    if not seed:
        raise ValueError("seed must be non-empty")
    if length < 0:
        raise ValueError("length must be non-negative")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(seed, domain + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        )
        counter += 1
    return bytes(output[:length])


def prf_int(seed: bytes, domain: bytes, n_bits: int) -> int:
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    n_bytes = (n_bits + 7) // 8
    value = int.from_bytes(prf(seed, domain, n_bytes), "big")
    return value & ((1 << n_bits) - 1)


class LazyTable:
    """Seed-derived transition family evaluated on demand."""

    def __init__(self, seed: bytes, params: LNATParams):
        _require_bytes("seed", seed)
        if len(seed) != params.seed_size:
            raise ValueError(f"seed must be {params.seed_size} bytes")
        self.seed = seed
        self.params = params
        self._cache: dict[tuple[int, int], int] = {}

    def lookup(self, state: int, inp: int) -> int:
        if not isinstance(state, int) or not 0 <= state < (1 << self.params.n):
            raise ValueError("state is outside the parameter state space")
        if not isinstance(inp, int) or not 0 <= inp < (1 << self.params.m):
            raise ValueError("input is outside the parameter input alphabet")
        key = (state, inp)
        if key not in self._cache:
            state_bytes = (self.params.n + 7) // 8
            input_bytes = (self.params.m + 7) // 8
            message = (
                _domain(self.params, b"DELTA")
                + state.to_bytes(state_bytes, "big")
                + inp.to_bytes(input_bytes, "big")
            )
            self._cache[key] = prf_int(self.seed, message, self.params.n)
            if len(self._cache) > 4096:
                del self._cache[next(iter(self._cache))]
        return self._cache[key]

    def clear_cache(self) -> None:
        self._cache.clear()


def observation_bit(seed: bytes, state: int, step: int, params: LNATParams) -> int:
    """Keyed one-bit observation for EXP2.

    This avoids publishing a fixed coordinate projection of each internal state.
    It is still only a research design choice; it is not evidence of hardness.
    """
    _require_bytes("seed", seed)
    if len(seed) != params.seed_size:
        raise ValueError(f"seed must be {params.seed_size} bytes")
    if not isinstance(state, int) or not 0 <= state < (1 << params.n):
        raise ValueError("state is outside the parameter state space")
    if not isinstance(step, int) or step < 0:
        raise ValueError("step must be a non-negative integer")
    state_bytes = (params.n + 7) // 8
    raw = prf(
        seed,
        _domain(params, b"OBS")
        + step.to_bytes(8, "big")
        + state.to_bytes(state_bytes, "big"),
        1,
    )
    return raw[0] & 1


def add_noise(bit: int, eta: float, rng=None) -> int:
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    if not 0.0 <= eta <= 1.0:
        raise ValueError("eta must be in [0, 1]")
    if rng is None:
        rng = secrets.SystemRandom()
    return bit ^ 1 if rng.random() < eta else bit


class LNATAutomaton:
    """Reference runner for LNAT-EXP2."""

    def __init__(self, seed: bytes, params: LNATParams = LNAT128):
        _require_bytes("seed", seed)
        if len(seed) != params.seed_size:
            raise ValueError(f"seed must be {params.seed_size} bytes")
        self.seed = seed
        self.params = params
        self.table = LazyTable(seed, params)

    def derive_q0(self, nonce: bytes) -> int:
        _require_bytes("nonce", nonce)
        if not nonce:
            raise ValueError("nonce must be non-empty")
        return prf_int(self.seed, _domain(self.params, b"Q0") + nonce, self.params.n)

    def run(
        self,
        q0: int,
        input_sequence: Iterable[int],
        *,
        noisy: bool = False,
        rng=None,
    ) -> list[int]:
        if not isinstance(q0, int) or not 0 <= q0 < (1 << self.params.n):
            raise ValueError("q0 is outside the parameter state space")
        state = q0
        outputs: list[int] = []
        for step, inp in enumerate(input_sequence, start=1):
            state = self.table.lookup(state, inp)
            bit = observation_bit(self.seed, state, step, self.params)
            if noisy:
                bit = add_noise(bit, self.params.eta, rng)
            outputs.append(bit)
        return outputs

    def run_noiseless(self, q0: int, input_sequence: Iterable[int]) -> list[int]:
        return self.run(q0, input_sequence, noisy=False)

    def run_noisy(self, q0: int, input_sequence: Iterable[int], rng=None) -> list[int]:
        return self.run(q0, input_sequence, noisy=True, rng=rng)


def generate_seed(params: LNATParams = LNAT128) -> bytes:
    return secrets.token_bytes(params.seed_size)


def generate_input_sequence(
    params: LNATParams,
    seed_A: bytes | None = None,
) -> tuple[bytes, list[int]]:
    if seed_A is None:
        seed_A = secrets.token_bytes(32)
    _require_bytes("seed_A", seed_A)
    if len(seed_A) != 32:
        raise ValueError("seed_A must be 32 bytes")
    bytes_per_value = (params.m + 7) // 8
    raw = prf(
        seed_A,
        _domain(params, b"INPUT-SEQUENCE"),
        params.T * bytes_per_value,
    )
    mask = (1 << params.m) - 1
    values = []
    for index in range(params.T):
        start = index * bytes_per_value
        chunk = raw[start : start + bytes_per_value]
        values.append(int.from_bytes(chunk, "big") & mask)
    return seed_A, values


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    """Canonical MSB-first bit packing used by research tooling."""
    bit_list = list(bits)
    if any(bit not in (0, 1) for bit in bit_list):
        raise ValueError("bits must contain only 0 or 1")
    padded = bit_list + [0] * ((-len(bit_list)) % 8)
    out = bytearray()
    for offset in range(0, len(padded), 8):
        byte = 0
        for bit in padded[offset : offset + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)
