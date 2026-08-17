"""Attack-oriented analysis utilities for LNAT toy profiles."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable

from lnat_core import LNATAutomaton, generate_input_sequence, observation_bit
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


@dataclass(frozen=True)
class PrunedRecoveryResult:
    """Result of exact branch-and-bound exhaustive seed recovery."""

    seed: bytes
    score: int
    candidates_tested: int
    candidates_pruned: int
    bit_comparisons: int
    full_bit_comparisons: int

    @property
    def saved_bit_comparisons(self) -> int:
        return self.full_bit_comparisons - self.bit_comparisons

    @property
    def savings_fraction(self) -> float:
        if self.full_bit_comparisons == 0:
            return 0.0
        return self.saved_bit_comparisons / self.full_bit_comparisons


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


def _validate_observations(
    observations: Iterable[TraceObservation], params: LNATParams
) -> tuple[TraceObservation, ...]:
    observations = tuple(observations)
    if not observations:
        raise ValueError("at least one observation is required")
    for obs in observations:
        if len(obs.trace) != params.T:
            raise ValueError("observation trace length does not match profile")
    return observations


def score_seed(candidate_seed: bytes, observations: Iterable[TraceObservation], params: LNATParams) -> int:
    if len(candidate_seed) != params.seed_size:
        raise ValueError("candidate seed length does not match profile")
    observations = _validate_observations(observations, params)
    score = 0
    for obs in observations:
        predicted = make_observation(
            candidate_seed,
            params,
            nonce=obs.nonce,
            seed_A=obs.seed_A,
            noisy=False,
        )
        score += hamming_distance(predicted.trace, obs.trace)
    return score


def score_seed_bounded(
    candidate_seed: bytes,
    observations: Iterable[TraceObservation],
    params: LNATParams,
    *,
    cutoff: int | None,
) -> tuple[int, int, bool]:
    """Score a candidate and stop once it can no longer beat `cutoff`.

    Returns `(score_so_far, bit_comparisons, pruned)`. If `pruned` is false,
    the score is the exact full Hamming score. If it is true, the final score
    is guaranteed to be at least `cutoff`, so the candidate cannot improve the
    current best score.
    """
    if len(candidate_seed) != params.seed_size:
        raise ValueError("candidate seed length does not match profile")
    observations = _validate_observations(observations, params)
    if cutoff is not None and cutoff < 0:
        raise ValueError("cutoff must be non-negative")
    if cutoff == 0:
        return 0, 0, True

    score = 0
    compared = 0
    for obs in observations:
        automaton = LNATAutomaton(candidate_seed, params)
        q0 = automaton.derive_q0(obs.nonce)
        _, inputs = generate_input_sequence(params, obs.seed_A)
        state = q0
        for step, (inp, observed) in enumerate(zip(inputs, obs.trace), start=1):
            state = automaton.table.lookup(state, inp)
            predicted = observation_bit(candidate_seed, state, step, params)
            compared += 1
            if predicted != observed:
                score += 1
                if cutoff is not None and score >= cutoff:
                    return score, compared, True
    return score, compared, False


def _candidate_limit(params: LNATParams, max_candidates: int | None) -> int:
    total = 1 << (8 * params.seed_size)
    if max_candidates is not None:
        if max_candidates <= 0:
            raise ValueError("max_candidates must be positive")
        total = min(total, max_candidates)
    return total


def exhaustive_seed_recovery(
    observations: Iterable[TraceObservation],
    params: LNATParams,
    *,
    max_candidates: int | None = None,
) -> tuple[bytes, int, int]:
    """Recover the best toy seed by exhaustive minimum-Hamming-distance search."""
    observations = _validate_observations(observations, params)
    total = _candidate_limit(params, max_candidates)
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
            if score == 0:
                break
    assert best_score is not None
    return best_seed, best_score, tested


def exhaustive_seed_recovery_pruned(
    observations: Iterable[TraceObservation],
    params: LNATParams,
    *,
    max_candidates: int | None = None,
) -> PrunedRecoveryResult:
    """Exact exhaustive recovery with branch-and-bound Hamming pruning.

    The search result is identical to the unpruned minimum-Hamming objective.
    Once a candidate accumulates at least the current best number of mismatches,
    remaining trace bits cannot make it better, so evaluation stops early.
    """
    observations = _validate_observations(observations, params)
    total = _candidate_limit(params, max_candidates)
    bits_per_candidate = len(observations) * params.T

    best_seed = b""
    best_score: int | None = None
    tested = 0
    pruned = 0
    compared = 0

    for value in range(total):
        if best_score == 0:
            break
        tested += 1
        candidate = value.to_bytes(params.seed_size, "big")
        score, used, was_pruned = score_seed_bounded(
            candidate,
            observations,
            params,
            cutoff=best_score,
        )
        compared += used
        if was_pruned:
            pruned += 1
            continue
        if best_score is None or score < best_score:
            best_seed = candidate
            best_score = score

    assert best_score is not None
    return PrunedRecoveryResult(
        seed=best_seed,
        score=best_score,
        candidates_tested=tested,
        candidates_pruned=pruned,
        bit_comparisons=compared,
        full_bit_comparisons=tested * bits_per_candidate,
    )


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
