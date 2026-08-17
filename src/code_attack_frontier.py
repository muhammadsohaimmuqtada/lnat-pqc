"""Attack-aware parameter screening for the random-code research KEM.

The active screen keeps attack metrics separate:

* Prange: expected information-set trial bits.
* Stern: transparent reference-operation bits.
* Dumer: transparent enlarged-information-set reference-operation bits.

These are different units and none is a proven security level. A profile can be
required to satisfy all requested floors plus the conservative full-KEM
correctness gate.
"""

from __future__ import annotations

from dataclasses import dataclass

from code_attacks import prange_expected_trial_bits
from code_dumer import DumerCostPoint, best_dumer_cost
from code_profile_audit import (
    fixed_weight_intersection_odd_probability,
    minimum_repetitions_for_kem_failure,
    sparse_witness_enumeration_bits,
)
from code_stern import SternCostPoint, best_stern_cost


@dataclass(frozen=True)
class AttackAwareKEMParameterCandidate:
    n: int
    k: int
    secret_weight: int
    encryption_error_weight: int
    prange_expected_trial_bits: float
    stern_modeled_ops_bits: float
    stern_p: int
    stern_l: int
    stern_memory_entry_bits: float
    dumer_modeled_ops_bits: float
    dumer_p: int
    dumer_l: int
    dumer_memory_entry_bits: float
    full_witness_enumeration_bits: float
    encapsulated_bits: int
    repetitions: int
    cutoff_ones: int
    threshold: float
    bit0_failure_probability: float
    bit1_failure_probability: float
    modeled_seed_failure_probability: float
    conservative_kem_failure_bound: float

    @property
    def worst_bit_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)


def _validate_frontier_args(
    *,
    n: int,
    k: int,
    prange_trial_floor_bits: float,
    stern_operation_floor_bits: float,
    dumer_operation_floor_bits: float,
    encryption_error_weight: int,
    encapsulated_bits: int,
    kem_failure_ceiling: float,
    max_repetitions: int,
    stern_max_p: int,
    stern_max_l: int,
    dumer_max_p: int,
    dumer_max_l: int,
) -> None:
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if prange_trial_floor_bits < 0:
        raise ValueError("prange_trial_floor_bits must be non-negative")
    if stern_operation_floor_bits < 0:
        raise ValueError("stern_operation_floor_bits must be non-negative")
    if dumer_operation_floor_bits < 0:
        raise ValueError("dumer_operation_floor_bits must be non-negative")
    if not 0 <= encryption_error_weight <= n:
        raise ValueError("encryption_error_weight must be in [0, n]")
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")
    if not 0.0 < kem_failure_ceiling < 1.0:
        raise ValueError("kem_failure_ceiling must be in (0, 1)")
    if max_repetitions <= 0:
        raise ValueError("max_repetitions must be positive")
    if stern_max_p <= 0 or stern_max_l <= 0:
        raise ValueError("Stern search limits must be positive")
    if dumer_max_p < 2 or dumer_max_l <= 0:
        raise ValueError("Dumer search requires max_p>=2 and max_l>0")


def minimum_weight_for_stern_operation_floor(
    n: int,
    k: int,
    bits: float,
    *,
    max_p: int = 4,
    max_l: int = 32,
) -> tuple[int, SternCostPoint] | None:
    """Return the first weight meeting a Stern reference-operation floor."""
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if bits < 0:
        raise ValueError("bits must be non-negative")
    if max_p <= 0 or max_l <= 0:
        raise ValueError("max_p and max_l must be positive")
    for weight in range(2, n - k + 1):
        try:
            point = best_stern_cost(n, k, weight, max_p=max_p, max_l=max_l)
        except ValueError:
            continue
        if point.estimated_total_ops_bits >= bits:
            return weight, point
    return None


def minimum_weight_for_dumer_operation_floor(
    n: int,
    k: int,
    bits: float,
    *,
    max_p: int = 8,
    max_l: int = 32,
) -> tuple[int, DumerCostPoint] | None:
    """Return the first weight meeting a Dumer reference-operation floor."""
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if bits < 0:
        raise ValueError("bits must be non-negative")
    if max_p < 2 or max_l <= 0:
        raise ValueError("max_p must be >=2 and max_l positive")
    for weight in range(2, n - k + 1):
        try:
            point = best_dumer_cost(n, k, weight, max_p=max_p, max_l=max_l)
        except ValueError:
            continue
        if point.estimated_total_ops_bits >= bits:
            return weight, point
    return None


def screen_attack_aware_kem_candidate(
    *,
    n: int,
    k: int,
    prange_trial_floor_bits: float,
    stern_operation_floor_bits: float,
    encryption_error_weight: int,
    encapsulated_bits: int,
    kem_failure_ceiling: float,
    dumer_operation_floor_bits: float = 0.0,
    max_repetitions: int = 1024,
    stern_max_p: int = 4,
    stern_max_l: int = 32,
    dumer_max_p: int = 8,
    dumer_max_l: int = 32,
) -> AttackAwareKEMParameterCandidate | None:
    """Return the minimum-weight profile passing all requested research gates."""
    _validate_frontier_args(
        n=n,
        k=k,
        prange_trial_floor_bits=prange_trial_floor_bits,
        stern_operation_floor_bits=stern_operation_floor_bits,
        dumer_operation_floor_bits=dumer_operation_floor_bits,
        encryption_error_weight=encryption_error_weight,
        encapsulated_bits=encapsulated_bits,
        kem_failure_ceiling=kem_failure_ceiling,
        max_repetitions=max_repetitions,
        stern_max_p=stern_max_p,
        stern_max_l=stern_max_l,
        dumer_max_p=dumer_max_p,
        dumer_max_l=dumer_max_l,
    )

    for weight in range(2, n - k + 1):
        prange_bits = prange_expected_trial_bits(n, k, weight)
        if prange_bits < prange_trial_floor_bits:
            continue

        try:
            stern = best_stern_cost(n, k, weight, max_p=stern_max_p, max_l=stern_max_l)
            dumer = best_dumer_cost(n, k, weight, max_p=dumer_max_p, max_l=dumer_max_l)
        except ValueError:
            continue
        if stern.estimated_total_ops_bits < stern_operation_floor_bits:
            continue
        if dumer.estimated_total_ops_bits < dumer_operation_floor_bits:
            continue

        zero_one_probability = fixed_weight_intersection_odd_probability(
            n,
            weight,
            encryption_error_weight,
        )
        if zero_one_probability >= 0.5:
            continue

        kem = minimum_repetitions_for_kem_failure(
            zero_one_probability,
            encapsulated_bits,
            kem_failure_ceiling,
            max_repetitions=max_repetitions,
        )
        if kem is None:
            continue

        decision = kem.decision
        return AttackAwareKEMParameterCandidate(
            n=n,
            k=k,
            secret_weight=weight,
            encryption_error_weight=encryption_error_weight,
            prange_expected_trial_bits=prange_bits,
            stern_modeled_ops_bits=stern.estimated_total_ops_bits,
            stern_p=stern.p,
            stern_l=stern.l,
            stern_memory_entry_bits=stern.estimated_memory_bits,
            dumer_modeled_ops_bits=dumer.estimated_total_ops_bits,
            dumer_p=dumer.p,
            dumer_l=dumer.l,
            dumer_memory_entry_bits=dumer.estimated_memory_bits,
            full_witness_enumeration_bits=sparse_witness_enumeration_bits(n, weight),
            encapsulated_bits=encapsulated_bits,
            repetitions=decision.repetitions,
            cutoff_ones=decision.cutoff_ones,
            threshold=decision.threshold,
            bit0_failure_probability=decision.bit0_failure_probability,
            bit1_failure_probability=decision.bit1_failure_probability,
            modeled_seed_failure_probability=kem.modeled_seed_failure_probability,
            conservative_kem_failure_bound=kem.conservative_union_bound,
        )
    return None
