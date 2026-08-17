"""Modern-ISD-aware screening for shortlisted random-code KEM profiles.

The older local frontier scanned witness weight upward and treated a local Stern
reference-operation floor as its strongest gate. Maintained finite-parameter
estimation showed that assumption is unsafe: denser error weights can be easier
for modern ISD because many sparse solutions may exist.

This module evaluates explicit ``(n, k, w)`` points. It gates them on full-KEM
correctness and on the cheaper of:

* the pinned maintained syndrome-decoding estimator; and
* direct enumeration of all weight-w supports.

Crossing a requested modeled-work floor is a research screen, not a proof of
cryptographic security.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from code_attacks import prange_expected_trial_bits
from code_profile_audit import (
    fixed_weight_intersection_odd_probability,
    minimum_repetitions_for_kem_failure,
    sparse_witness_enumeration_bits,
)
from code_sd_estimator import UpstreamISDReport, estimate_upstream_isd

EstimatorFn = Callable[[int, int, int], UpstreamISDReport]

# Smallest point measured in the 2026-08-17 focused rate-1/2 sweep that clears
# a 128-bit modeled-work screen in cryptographic-estimators 2.1.1. This is a
# regression/research candidate only, not a deployment parameter set.
ACTIVE_RESEARCH_POINT = (1072, 536, 117)
BELOW_FLOOR_NEIGHBOR = (1056, 528, 116)


@dataclass(frozen=True)
class ModernISDPolicy:
    modeled_attack_floor_bits: float
    encryption_error_weight: int = 1
    encapsulated_bits: int = 128
    kem_failure_ceiling: float = 1e-9
    max_repetitions: int = 4096
    prange_prefilter_bits: float = 0.0

    def __post_init__(self) -> None:
        if self.modeled_attack_floor_bits < 0:
            raise ValueError("modeled_attack_floor_bits must be non-negative")
        if self.encryption_error_weight < 0:
            raise ValueError("encryption_error_weight must be non-negative")
        if self.encapsulated_bits <= 0:
            raise ValueError("encapsulated_bits must be positive")
        if not 0.0 < self.kem_failure_ceiling < 1.0:
            raise ValueError("kem_failure_ceiling must be in (0, 1)")
        if self.max_repetitions <= 0:
            raise ValueError("max_repetitions must be positive")
        if self.prange_prefilter_bits < 0:
            raise ValueError("prange_prefilter_bits must be non-negative")


@dataclass(frozen=True)
class ModernISDKEMParameterCandidate:
    n: int
    k: int
    secret_weight: int
    encryption_error_weight: int
    support_enumeration_bits: float
    prange_expected_trial_bits: float
    encapsulated_bits: int
    repetitions: int
    cutoff_ones: int
    threshold: float
    bit0_failure_probability: float
    bit1_failure_probability: float
    modeled_seed_failure_probability: float
    conservative_kem_failure_bound: float
    estimator_package_version: str
    upstream_fastest_algorithm: str
    upstream_attack_time_bits: float
    upstream_attack_memory_bits: float | None
    upstream_algorithm_parameters: dict[str, object]
    effective_attack: str
    effective_attack_bits: float

    @property
    def worst_bit_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)


def _validate_point(n: int, k: int, weight: int, policy: ModernISDPolicy) -> None:
    if not isinstance(n, int) or not isinstance(k, int) or not isinstance(weight, int):
        raise TypeError("n, k, and weight must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 1 <= weight <= n - k:
        raise ValueError("weight must be in [1, n-k]")
    if policy.encryption_error_weight > n:
        raise ValueError("encryption_error_weight must not exceed n")


def evaluate_modern_isd_candidate(
    n: int,
    k: int,
    weight: int,
    policy: ModernISDPolicy,
    *,
    estimate_fn: EstimatorFn = estimate_upstream_isd,
) -> ModernISDKEMParameterCandidate | None:
    """Evaluate one explicit point against correctness and attack screens."""
    _validate_point(n, k, weight, policy)

    prange_bits = prange_expected_trial_bits(n, k, weight)
    if prange_bits < policy.prange_prefilter_bits:
        return None

    zero_one_probability = fixed_weight_intersection_odd_probability(
        n,
        weight,
        policy.encryption_error_weight,
    )
    if zero_one_probability >= 0.5:
        return None

    kem = minimum_repetitions_for_kem_failure(
        zero_one_probability,
        policy.encapsulated_bits,
        policy.kem_failure_ceiling,
        max_repetitions=policy.max_repetitions,
    )
    if kem is None:
        return None

    support_bits = sparse_witness_enumeration_bits(n, weight)
    report = estimate_fn(n, k, weight)
    fastest = report.fastest

    if support_bits <= fastest.time_bits:
        effective_attack = "SupportEnumeration"
        effective_bits = support_bits
    else:
        effective_attack = fastest.algorithm
        effective_bits = fastest.time_bits

    if effective_bits < policy.modeled_attack_floor_bits:
        return None

    decision = kem.decision
    return ModernISDKEMParameterCandidate(
        n=n,
        k=k,
        secret_weight=weight,
        encryption_error_weight=policy.encryption_error_weight,
        support_enumeration_bits=support_bits,
        prange_expected_trial_bits=prange_bits,
        encapsulated_bits=policy.encapsulated_bits,
        repetitions=decision.repetitions,
        cutoff_ones=decision.cutoff_ones,
        threshold=decision.threshold,
        bit0_failure_probability=decision.bit0_failure_probability,
        bit1_failure_probability=decision.bit1_failure_probability,
        modeled_seed_failure_probability=kem.modeled_seed_failure_probability,
        conservative_kem_failure_bound=kem.conservative_union_bound,
        estimator_package_version=report.package_version,
        upstream_fastest_algorithm=fastest.algorithm,
        upstream_attack_time_bits=fastest.time_bits,
        upstream_attack_memory_bits=fastest.memory_bits,
        upstream_algorithm_parameters=dict(fastest.parameters),
        effective_attack=effective_attack,
        effective_attack_bits=effective_bits,
    )


def select_first_modern_isd_candidate(
    points: Iterable[tuple[int, int, int]],
    policy: ModernISDPolicy,
    *,
    estimate_fn: EstimatorFn = estimate_upstream_isd,
) -> ModernISDKEMParameterCandidate | None:
    """Return the first explicitly ordered point that passes every gate.

    The caller owns candidate ordering. No monotonicity in ``n`` or ``w`` is
    inferred.
    """
    for n, k, weight in points:
        candidate = evaluate_modern_isd_candidate(
            n,
            k,
            weight,
            policy,
            estimate_fn=estimate_fn,
        )
        if candidate is not None:
            return candidate
    return None
