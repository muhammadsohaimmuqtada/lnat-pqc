"""Modern attack/correctness gate for random-code LNAT research profiles.

The serious parameter screen uses the cheapest public attack currently wired
into the repository, not the LNAT seed length and not a local reference model
in isolation.

For a candidate ``(n, k, w)``:

    effective attack bits = min(
        pinned maintained syndrome-decoding estimate,
        log2(C(n, w)) direct support enumeration,
    )

The result is then combined with the exact fixed-weight intersection model and
the conservative full-KEM failure bound.

Estimator output is a research screening model, not a proof of cryptographic
security. Crossing a numeric floor means only that the candidate survives the
attack models currently evaluated here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from code_profile_audit import (
    fixed_weight_intersection_odd_probability,
    minimum_repetitions_for_kem_failure,
    sparse_witness_enumeration_bits,
)
from code_sd_estimator import UpstreamISDReport, estimate_upstream_isd


class Estimator(Protocol):
    def __call__(self, n: int, k: int, weight: int) -> UpstreamISDReport: ...


@dataclass(frozen=True)
class ModernAttackAssessment:
    n: int
    k: int
    weight: int
    upstream_algorithm: str
    upstream_time_bits: float
    upstream_memory_bits: float | None
    upstream_package_version: str
    support_enumeration_bits: float
    effective_attack_bits: float
    effective_attack: str
    encryption_error_weight: int
    encapsulated_bits: int
    repetitions: int | None
    cutoff_ones: int | None
    threshold: float | None
    bit0_failure_probability: float | None
    bit1_failure_probability: float | None
    modeled_seed_failure_probability: float | None
    conservative_kem_failure_bound: float | None

    @property
    def correctness_feasible(self) -> bool:
        return self.repetitions is not None

    def passes(self, attack_floor_bits: float, kem_failure_ceiling: float) -> bool:
        if attack_floor_bits < 0:
            raise ValueError("attack_floor_bits must be non-negative")
        if not 0.0 < kem_failure_ceiling < 1.0:
            raise ValueError("kem_failure_ceiling must be in (0, 1)")
        return (
            self.correctness_feasible
            and self.effective_attack_bits >= attack_floor_bits
            and self.conservative_kem_failure_bound is not None
            and self.conservative_kem_failure_bound <= kem_failure_ceiling
        )


def _validate_candidate(
    n: int,
    k: int,
    weight: int,
    encryption_error_weight: int,
    encapsulated_bits: int,
    kem_failure_ceiling: float,
    max_repetitions: int,
) -> None:
    if not isinstance(n, int) or not isinstance(k, int) or not isinstance(weight, int):
        raise TypeError("n, k, and weight must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 < weight <= n - k:
        raise ValueError("weight must be in [1, n-k]")
    if not 0 <= encryption_error_weight <= n:
        raise ValueError("encryption_error_weight must be in [0, n]")
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")
    if not 0.0 < kem_failure_ceiling < 1.0:
        raise ValueError("kem_failure_ceiling must be in (0, 1)")
    if max_repetitions <= 0:
        raise ValueError("max_repetitions must be positive")


def assess_modern_candidate(
    n: int,
    k: int,
    weight: int,
    *,
    encryption_error_weight: int = 1,
    encapsulated_bits: int = 128,
    kem_failure_ceiling: float = 1e-9,
    max_repetitions: int = 4096,
    estimator: Estimator = estimate_upstream_isd,
) -> ModernAttackAssessment:
    """Assess one candidate against modern public attacks and KEM correctness.

    ``estimator`` is injectable so ordinary unit tests remain deterministic and
    dependency-free. Dedicated estimator CI exercises the pinned upstream
    package itself.
    """
    _validate_candidate(
        n,
        k,
        weight,
        encryption_error_weight,
        encapsulated_bits,
        kem_failure_ceiling,
        max_repetitions,
    )
    if not callable(estimator):
        raise TypeError("estimator must be callable")

    report = estimator(n, k, weight)
    fastest = report.fastest
    support_bits = sparse_witness_enumeration_bits(n, weight)
    if fastest.time_bits <= support_bits:
        effective_bits = fastest.time_bits
        effective_attack = fastest.algorithm
    else:
        effective_bits = support_bits
        effective_attack = "SupportEnumeration"

    odd_probability = fixed_weight_intersection_odd_probability(
        n,
        weight,
        encryption_error_weight,
    )
    kem = None
    if odd_probability < 0.5:
        kem = minimum_repetitions_for_kem_failure(
            odd_probability,
            encapsulated_bits,
            kem_failure_ceiling,
            max_repetitions=max_repetitions,
        )

    if kem is None:
        return ModernAttackAssessment(
            n=n,
            k=k,
            weight=weight,
            upstream_algorithm=fastest.algorithm,
            upstream_time_bits=fastest.time_bits,
            upstream_memory_bits=fastest.memory_bits,
            upstream_package_version=report.package_version,
            support_enumeration_bits=support_bits,
            effective_attack_bits=effective_bits,
            effective_attack=effective_attack,
            encryption_error_weight=encryption_error_weight,
            encapsulated_bits=encapsulated_bits,
            repetitions=None,
            cutoff_ones=None,
            threshold=None,
            bit0_failure_probability=None,
            bit1_failure_probability=None,
            modeled_seed_failure_probability=None,
            conservative_kem_failure_bound=None,
        )

    decision = kem.decision
    return ModernAttackAssessment(
        n=n,
        k=k,
        weight=weight,
        upstream_algorithm=fastest.algorithm,
        upstream_time_bits=fastest.time_bits,
        upstream_memory_bits=fastest.memory_bits,
        upstream_package_version=report.package_version,
        support_enumeration_bits=support_bits,
        effective_attack_bits=effective_bits,
        effective_attack=effective_attack,
        encryption_error_weight=encryption_error_weight,
        encapsulated_bits=encapsulated_bits,
        repetitions=decision.repetitions,
        cutoff_ones=decision.cutoff_ones,
        threshold=decision.threshold,
        bit0_failure_probability=decision.bit0_failure_probability,
        bit1_failure_probability=decision.bit1_failure_probability,
        modeled_seed_failure_probability=kem.modeled_seed_failure_probability,
        conservative_kem_failure_bound=kem.conservative_union_bound,
    )


def screen_modern_candidate(
    n: int,
    k: int,
    weight: int,
    *,
    attack_floor_bits: float,
    encryption_error_weight: int = 1,
    encapsulated_bits: int = 128,
    kem_failure_ceiling: float = 1e-9,
    max_repetitions: int = 4096,
    estimator: Estimator = estimate_upstream_isd,
) -> ModernAttackAssessment | None:
    """Return the assessment only when attack and correctness gates pass."""
    if attack_floor_bits < 0:
        raise ValueError("attack_floor_bits must be non-negative")
    assessment = assess_modern_candidate(
        n,
        k,
        weight,
        encryption_error_weight=encryption_error_weight,
        encapsulated_bits=encapsulated_bits,
        kem_failure_ceiling=kem_failure_ceiling,
        max_repetitions=max_repetitions,
        estimator=estimator,
    )
    return assessment if assessment.passes(attack_floor_bits, kem_failure_ceiling) else None
