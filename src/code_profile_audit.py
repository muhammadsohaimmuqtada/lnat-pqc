"""Correctness and public-attack audits for code-based research profiles.

This module does not estimate full cryptanalytic security. It reports necessary
checks only:

1. full sparse-witness enumeration size C(n,w);
2. a Prange information-set decoding iteration model;
3. exact per-bit decryption-failure probabilities under the fixed-weight model;
4. composition of those bit failures across an encapsulated random seed; and
5. necessary parameter frontiers using attack and correctness filters.

Passing these checks is necessary, never sufficient. More advanced decoding
attacks, dependencies outside the reference randomness model, and the
polynomial work inside each attack iteration need separate analysis.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_attacks import prange_expected_information_sets, prange_expected_trial_bits
from code_pke_reference import CodePKEParams


@dataclass(frozen=True)
class CodeProfileAudit:
    params: CodePKEParams
    witness_space_size: int
    trivial_enumeration_bits: float
    prange_expected_information_sets: float
    prange_expected_trial_bits: float
    zero_inner_product_one_probability: float
    decision_cutoff_ones: int
    bit0_failure_probability: float
    bit1_failure_probability: float

    @property
    def worst_bit_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)

    def meets_trivial_enumeration_floor(self, bits: float) -> bool:
        if bits < 0:
            raise ValueError("bits must be non-negative")
        return self.trivial_enumeration_bits >= bits

    def meets_prange_trial_floor(self, bits: float) -> bool:
        if bits < 0:
            raise ValueError("bits must be non-negative")
        return self.prange_expected_trial_bits >= bits

    def meets_failure_ceiling(self, probability: float) -> bool:
        if not 0.0 <= probability <= 1.0:
            raise ValueError("probability must be in [0, 1]")
        return self.worst_bit_failure_probability <= probability


@dataclass(frozen=True)
class DecisionRuleAudit:
    """Best threshold for one encrypted bit at a fixed repetition count."""

    repetitions: int
    cutoff_ones: int
    threshold: float
    bit0_failure_probability: float
    bit1_failure_probability: float

    @property
    def worst_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)

    @property
    def random_bit_failure_probability(self) -> float:
        """Failure probability for one uniformly random encapsulated bit."""
        return (self.bit0_failure_probability + self.bit1_failure_probability) / 2.0


@dataclass(frozen=True)
class KEMDecisionAudit:
    """Full encapsulated-seed correctness for one repetition/cutoff choice."""

    decision: DecisionRuleAudit
    encapsulated_bits: int
    modeled_seed_failure_probability: float
    conservative_union_bound: float


@dataclass(frozen=True)
class NecessaryParameterCandidate:
    """Legacy per-bit necessary screening point; not a security level."""

    n: int
    k: int
    secret_weight: int
    encryption_error_weight: int
    prange_expected_trial_bits: float
    full_witness_enumeration_bits: float
    repetitions: int
    cutoff_ones: int
    threshold: float
    bit0_failure_probability: float
    bit1_failure_probability: float

    @property
    def worst_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)


@dataclass(frozen=True)
class NecessaryKEMParameterCandidate:
    """Profile passing necessary attack and *full-KEM* correctness filters."""

    n: int
    k: int
    secret_weight: int
    encryption_error_weight: int
    prange_expected_trial_bits: float
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


def sparse_witness_space_size(n: int, weight: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    return math.comb(n, weight)


def sparse_witness_enumeration_bits(n: int, weight: int) -> float:
    size = sparse_witness_space_size(n, weight)
    return math.log2(size) if size > 0 else 0.0


def fixed_weight_intersection_odd_probability(
    n: int,
    left_weight: int,
    right_weight: int,
) -> float:
    """Probability that two independent fixed-weight supports overlap oddly."""
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= left_weight <= n or not 0 <= right_weight <= n:
        raise ValueError("weights must be in [0, n]")

    denominator = math.comb(n, right_weight)
    if denominator == 0:
        return 0.0
    lower = max(0, right_weight - (n - left_weight))
    upper = min(left_weight, right_weight)
    numerator = 0
    for overlap in range(lower, upper + 1):
        if overlap & 1:
            numerator += math.comb(left_weight, overlap) * math.comb(
                n - left_weight,
                right_weight - overlap,
            )
    return numerator / denominator


def _binomial_pmf_sequence(trials: int, probability: float) -> tuple[float, ...]:
    if trials < 0:
        raise ValueError("trials must be non-negative")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")
    if probability == 0.0:
        return (1.0, *([0.0] * trials))
    if probability == 1.0:
        return (*([0.0] * trials), 1.0)

    q = 1.0 - probability
    probabilities = [q**trials]
    for count in range(trials):
        probabilities.append(
            probabilities[-1]
            * (trials - count)
            / (count + 1)
            * probability
            / q
        )
    return tuple(probabilities)


def _cumulative(probabilities: tuple[float, ...]) -> tuple[float, ...]:
    total = 0.0
    values = []
    for probability in probabilities:
        total += probability
        values.append(min(1.0, max(0.0, total)))
    return tuple(values)


def binomial_cdf(trials: int, probability: float, inclusive_max: int) -> float:
    if inclusive_max < 0:
        return 0.0
    if inclusive_max >= trials:
        return 1.0
    return _cumulative(_binomial_pmf_sequence(trials, probability))[inclusive_max]


def binomial_tail(trials: int, probability: float, inclusive_min: int) -> float:
    if inclusive_min <= 0:
        return 1.0
    if inclusive_min > trials:
        return 0.0
    return max(0.0, 1.0 - binomial_cdf(trials, probability, inclusive_min - 1))


def kem_seed_failure_probability(
    bit0_failure_probability: float,
    bit1_failure_probability: float,
    encapsulated_bits: int,
) -> float:
    """Modeled failure for a uniformly random seed under independent bit encryptions.

    Each encapsulated seed bit is uniform, so the unconditional one-bit error
    probability is `(p0+p1)/2`. The reference KEM encrypts bits with fresh
    randomness, yielding the model `1-(1-p_avg)^m`. This is a model result, not
    a proof that every future construction has independent bit failures.
    """
    for name, probability in (
        ("bit0_failure_probability", bit0_failure_probability),
        ("bit1_failure_probability", bit1_failure_probability),
    ):
        if not 0.0 <= probability <= 1.0:
            raise ValueError(f"{name} must be in [0, 1]")
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")

    average = (bit0_failure_probability + bit1_failure_probability) / 2.0
    if average == 0.0:
        return 0.0
    if average == 1.0:
        return 1.0
    return -math.expm1(encapsulated_bits * math.log1p(-average))


def kem_failure_union_bound(
    bit0_failure_probability: float,
    bit1_failure_probability: float,
    encapsulated_bits: int,
) -> float:
    """Conservative union bound using the worse per-bit failure probability."""
    for probability in (bit0_failure_probability, bit1_failure_probability):
        if not 0.0 <= probability <= 1.0:
            raise ValueError("bit failure probabilities must be in [0, 1]")
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")
    return min(
        1.0,
        encapsulated_bits
        * max(bit0_failure_probability, bit1_failure_probability),
    )


def optimal_decision_for_repetitions(
    zero_one_probability: float,
    repetitions: int,
) -> DecisionRuleAudit:
    """Choose the cutoff minimizing the larger Enc(0)/Enc(1) bit failure."""
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    if not 0.0 <= zero_one_probability < 0.5:
        raise ValueError("zero_one_probability must be in [0, 0.5)")

    zero_cdf = _cumulative(_binomial_pmf_sequence(repetitions, zero_one_probability))
    one_cdf = _cumulative(_binomial_pmf_sequence(repetitions, 0.5))

    best: DecisionRuleAudit | None = None
    for cutoff in range(1, repetitions + 1):
        bit0_failure = max(0.0, 1.0 - zero_cdf[cutoff - 1])
        bit1_failure = one_cdf[cutoff - 1]
        decision = DecisionRuleAudit(
            repetitions=repetitions,
            cutoff_ones=cutoff,
            threshold=cutoff / repetitions,
            bit0_failure_probability=bit0_failure,
            bit1_failure_probability=bit1_failure,
        )
        if best is None or decision.worst_failure_probability < best.worst_failure_probability:
            best = decision

    assert best is not None
    return best


def minimum_repetitions_for_failure(
    zero_one_probability: float,
    failure_ceiling: float,
    *,
    max_repetitions: int = 512,
) -> DecisionRuleAudit | None:
    """Legacy per-bit screen: smallest repetitions meeting a bit-error ceiling."""
    if not 0.0 < failure_ceiling < 1.0:
        raise ValueError("failure_ceiling must be in (0, 1)")
    if max_repetitions <= 0:
        raise ValueError("max_repetitions must be positive")
    for repetitions in range(1, max_repetitions + 1):
        decision = optimal_decision_for_repetitions(zero_one_probability, repetitions)
        if decision.worst_failure_probability <= failure_ceiling:
            return decision
    return None


def minimum_repetitions_for_kem_failure(
    zero_one_probability: float,
    encapsulated_bits: int,
    failure_ceiling: float,
    *,
    max_repetitions: int = 1024,
) -> KEMDecisionAudit | None:
    """Smallest repetition count meeting a conservative full-KEM failure ceiling."""
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")
    if not 0.0 < failure_ceiling < 1.0:
        raise ValueError("failure_ceiling must be in (0, 1)")
    if max_repetitions <= 0:
        raise ValueError("max_repetitions must be positive")

    for repetitions in range(1, max_repetitions + 1):
        decision = optimal_decision_for_repetitions(zero_one_probability, repetitions)
        modeled = kem_seed_failure_probability(
            decision.bit0_failure_probability,
            decision.bit1_failure_probability,
            encapsulated_bits,
        )
        union = kem_failure_union_bound(
            decision.bit0_failure_probability,
            decision.bit1_failure_probability,
            encapsulated_bits,
        )
        if union <= failure_ceiling:
            return KEMDecisionAudit(
                decision=decision,
                encapsulated_bits=encapsulated_bits,
                modeled_seed_failure_probability=modeled,
                conservative_union_bound=union,
            )
    return None


def audit_code_profile(params: CodePKEParams) -> CodeProfileAudit:
    witness_size = sparse_witness_space_size(params.n, params.secret_weight)
    witness_bits = sparse_witness_enumeration_bits(params.n, params.secret_weight)
    prange_sets = prange_expected_information_sets(params.n, params.k, params.secret_weight)
    prange_bits = prange_expected_trial_bits(params.n, params.k, params.secret_weight)

    p_zero_one = fixed_weight_intersection_odd_probability(
        params.n,
        params.secret_weight,
        params.encryption_error_weight,
    )
    cutoff = math.ceil(params.zero_threshold * params.repetitions)
    bit0_failure = binomial_tail(params.repetitions, p_zero_one, cutoff)
    bit1_failure = binomial_cdf(params.repetitions, 0.5, cutoff - 1)

    return CodeProfileAudit(
        params=params,
        witness_space_size=witness_size,
        trivial_enumeration_bits=witness_bits,
        prange_expected_information_sets=prange_sets,
        prange_expected_trial_bits=prange_bits,
        zero_inner_product_one_probability=p_zero_one,
        decision_cutoff_ones=cutoff,
        bit0_failure_probability=bit0_failure,
        bit1_failure_probability=bit1_failure,
    )


def minimum_weight_for_trivial_floor(n: int, bits: float) -> int | None:
    if n <= 0:
        raise ValueError("n must be positive")
    if bits < 0:
        raise ValueError("bits must be non-negative")
    for weight in range(0, n // 2 + 1):
        if sparse_witness_enumeration_bits(n, weight) >= bits:
            return weight
    return None


def minimum_weight_for_prange_trial_floor(n: int, k: int, bits: float) -> int | None:
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if bits < 0:
        raise ValueError("bits must be non-negative")
    for weight in range(0, n - k + 1):
        if prange_expected_trial_bits(n, k, weight) >= bits:
            return weight
    return None


def screen_necessary_candidate(
    *,
    n: int,
    k: int,
    prange_trial_floor_bits: float,
    encryption_error_weight: int,
    failure_ceiling: float,
    max_repetitions: int = 512,
) -> NecessaryParameterCandidate | None:
    """Legacy per-bit frontier retained for reproducibility."""
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= encryption_error_weight <= n:
        raise ValueError("encryption_error_weight must be in [0, n]")
    if prange_trial_floor_bits < 0:
        raise ValueError("prange_trial_floor_bits must be non-negative")

    secret_weight = minimum_weight_for_prange_trial_floor(n, k, prange_trial_floor_bits)
    if secret_weight is None:
        return None
    p_zero_one = fixed_weight_intersection_odd_probability(
        n,
        secret_weight,
        encryption_error_weight,
    )
    if p_zero_one >= 0.5:
        return None
    decision = minimum_repetitions_for_failure(
        p_zero_one,
        failure_ceiling,
        max_repetitions=max_repetitions,
    )
    if decision is None:
        return None

    return NecessaryParameterCandidate(
        n=n,
        k=k,
        secret_weight=secret_weight,
        encryption_error_weight=encryption_error_weight,
        prange_expected_trial_bits=prange_expected_trial_bits(n, k, secret_weight),
        full_witness_enumeration_bits=sparse_witness_enumeration_bits(n, secret_weight),
        repetitions=decision.repetitions,
        cutoff_ones=decision.cutoff_ones,
        threshold=decision.threshold,
        bit0_failure_probability=decision.bit0_failure_probability,
        bit1_failure_probability=decision.bit1_failure_probability,
    )


def screen_necessary_kem_candidate(
    *,
    n: int,
    k: int,
    prange_trial_floor_bits: float,
    encryption_error_weight: int,
    encapsulated_bits: int,
    kem_failure_ceiling: float,
    max_repetitions: int = 1024,
) -> NecessaryKEMParameterCandidate | None:
    """Screen using a conservative failure ceiling for the complete seed."""
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= encryption_error_weight <= n:
        raise ValueError("encryption_error_weight must be in [0, n]")
    if prange_trial_floor_bits < 0:
        raise ValueError("prange_trial_floor_bits must be non-negative")
    if encapsulated_bits <= 0:
        raise ValueError("encapsulated_bits must be positive")

    secret_weight = minimum_weight_for_prange_trial_floor(n, k, prange_trial_floor_bits)
    if secret_weight is None:
        return None
    p_zero_one = fixed_weight_intersection_odd_probability(
        n,
        secret_weight,
        encryption_error_weight,
    )
    if p_zero_one >= 0.5:
        return None

    kem_decision = minimum_repetitions_for_kem_failure(
        p_zero_one,
        encapsulated_bits,
        kem_failure_ceiling,
        max_repetitions=max_repetitions,
    )
    if kem_decision is None:
        return None
    decision = kem_decision.decision

    return NecessaryKEMParameterCandidate(
        n=n,
        k=k,
        secret_weight=secret_weight,
        encryption_error_weight=encryption_error_weight,
        prange_expected_trial_bits=prange_expected_trial_bits(n, k, secret_weight),
        full_witness_enumeration_bits=sparse_witness_enumeration_bits(n, secret_weight),
        encapsulated_bits=encapsulated_bits,
        repetitions=decision.repetitions,
        cutoff_ones=decision.cutoff_ones,
        threshold=decision.threshold,
        bit0_failure_probability=decision.bit0_failure_probability,
        bit1_failure_probability=decision.bit1_failure_probability,
        modeled_seed_failure_probability=kem_decision.modeled_seed_failure_probability,
        conservative_kem_failure_bound=kem_decision.conservative_union_bound,
    )
