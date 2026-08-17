"""Attack-oriented analysis utilities for LNAT toy profiles."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable

from lnat_core import LNATAutomaton, generate_input_sequence
from lnat_params import LNATParams


@dataclass(frozen=True)
class TraceObservation:
    nonce: bytes
    seed_A: bytes
    trace: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.nonce:
            raise ValueError("nonce must be non-empty")
        if len(self.seed_A) != 32:
            raise ValueError("seed_A must be 32 bytes")
        if any(bit not in (0, 1) for bit in self.trace):
            raise ValueError("trace must contain only bits")


def hamming_distance(a: Iterable[int], b: Iterable[int]) -> int:
    left = tuple(a)
    right = tuple(b)
    if len(left) != len(right):
        raise ValueError("sequences must have equal length")
    return sum(x != y for x, y in zip(left, right))


def make_observation(
    seed: bytes,
    params: LNATParams,
    *,
    nonce: bytes,
    seed_A: bytes,
    noisy: bool = True,
    rng=None,
) -> TraceObservation:
    automaton = LNATAutomaton(seed, params)
    q0 = automaton.derive_q0(nonce)
    _, inputs = generate_input_sequence(params, seed_A)
    trace = (
        automaton.run_noisy(q0, inputs, rng=rng)
        if noisy
        else automaton.run_noiseless(q0, inputs)
    )
    return TraceObservation(nonce, seed_A, tuple(trace))


def score_seed(candidate_seed: bytes, observations: Iterable[TraceObservation], params: LNATParams) -> int:
    if len(candidate_seed) != params.seed_size:
        raise ValueError("candidate seed length does not match profile")
    score = 0
    count = 0
    for obs in observations:
        count += 1
        predicted = make_observation(
            candidate_seed,
            params,
            nonce=obs.nonce,
            seed_A=obs.seed_A,
            noisy=False,
        )
        score += hamming_distance(predicted.trace, obs.trace)
    if count == 0:
        raise ValueError("at least one observation is required")
    return score


def exhaustive_seed_recovery(
    observations: Iterable[TraceObservation],
    params: LNATParams,
    *,
    max_candidates: int | None = None,
) -> tuple[bytes, int, int]:
    """Recover the best toy seed by exhaustive minimum-Hamming-distance search.

    Returns `(seed, score, candidates_tested)`. This is intentionally only
    practical for tiny `seed_size` profiles and is provided to establish a real
    attack baseline rather than to claim security at large parameters.
    """
    observations = tuple(observations)
    if not observations:
        raise ValueError("at least one observation is required")
    total = 1 << (8 * params.seed_size)
    if max_candidates is not None:
        if max_candidates <= 0:
            raise ValueError("max_candidates must be positive")
        total = min(total, max_candidates)
    best_seed = b""
    best_score: int | None = None
    tested = 0
    for value in range(total):
        tested += 1
        candidate = value.to_bytes(params.seed_size, "big")
        score = score_seed(candidate, observations, params)
        if best_score is None or score < best_score:
            best_seed = candidate
            best_score = score
            if score == 0 and params.eta == 0.0:
                break
    assert best_score is not None
    return best_seed, best_score, tested


def monobit_bias(trace: Iterable[int]) -> float:
    bits = tuple(trace)
    if not bits:
        raise ValueError("trace must not be empty")
    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("trace must contain only bits")
    return sum(bits) / len(bits) - 0.5


def lag1_agreement(trace: Iterable[int]) -> float:
    bits = tuple(trace)
    if len(bits) < 2:
        raise ValueError("trace needs at least two bits")
    if any(bit not in (0, 1) for bit in bits):
        raise ValueError("trace must contain only bits")
    return sum(a == b for a, b in zip(bits, bits[1:])) / (len(bits) - 1)


def deterministic_rng(seed: int) -> random.Random:
    """Test-only RNG helper; never use this for cryptographic randomness."""
    return random.Random(seed)
