"""Correctness and public-attack audits for code-based research profiles.

This module does not estimate full cryptanalytic security. It reports necessary
checks only:

1. full sparse-witness enumeration size C(n,w);
2. a Prange information-set decoding iteration model, which can be far cheaper;
3. exact decryption-failure probabilities under the reference fixed-weight
   correctness model; and
4. a necessary parameter frontier that combines a requested Prange *trial*
   floor with a requested correctness-failure ceiling.

Passing these checks is necessary, never sufficient. More advanced decoding
attacks and the polynomial cost inside each iteration still need separate work.
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
        """Check only the logarithm of expected Prange information-set trials."""
        if bits < 0:
            raise ValueError("bits must be non-negative")
        return self.prange_expected_trial_bits >= bits

    def meets_failure_ceiling(self, probability: float) -> bool:
        if not 0.0 <= probability <= 1.0:
            raise ValueError("probability must be in [0, 1]")
        return self.worst_bit_failure_probability <= probability


@dataclass(frozen=True)
class DecisionRuleAudit:
    """Best threshold for a fixed repetition count under the toy model."""

    repetitions: int
    cutoff_ones: int
    threshold: float
    bit0_failure_probability: float
    bit1_failure_probability: float

    @property
    def worst_failure_probability(self) -> float:
        return max(self.bit0_failure_probability, self.bit1_failure_probability)


@dataclass(frozen=True)
class NecessaryParameterCandidate:
    """A profile passing only the repository's necessary screening filters.

    `prange_expected_trial_bits` is not a security level. It omits the
    polynomial work within each information-set trial and ignores stronger ISD
    variants. The object is named "candidate" only in the sense of "worth more
    analysis", never "safe to deploy".
    """

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
    """Return P[X=k] for k=0..trials using a stable adjacent-PMF recurrence."""
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


def optimal_decision_for_repetitions(
    zero_one_probability: float,
    repetitions: int,
) -> DecisionRuleAudit:
    """Choose the cutoff minimizing the larger Enc(0)/Enc(1) bit failure.

    Decapsulation returns zero when the observed number of one bits is strictly
    below `cutoff_ones`; therefore `threshold = cutoff_ones / repetitions`.
    """
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
    """Find the smallest repetition count whose optimal rule meets a ceiling."""
    if not 0.0 < failure_ceiling < 1.0:
        raise ValueError("failure_ceiling must be in (0, 1)")
    if max_repetitions <= 0:
        raise ValueError("max_repetitions must be positive")
    for repetitions in range(1, max_repetitions + 1):
        decision = optimal_decision_for_repetitions(
            zero_one_probability,
            repetitions,
        )
        if decision.worst_failure_probability <= failure_ceiling:
            return decision
    return None


def audit_code_profile(params: CodePKEParams) -> CodeProfileAudit:
    witness_size = sparse_witness_space_size(params.n, params.secret_weight)
    witness_bits = sparse_witness_enumeration_bits(params.n, params.secret_weight)
    prange_sets = prange_expected_information_sets(
        params.n,
        params.k,
        params.secret_weight,
    )
    prange_bits = prange_expected_trial_bits(
        params.n,
        params.k,
        params.secret_weight,
    )

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
    """Smallest w <= n/2 with log2(C(n,w)) >= `bits`, if one exists."""
    if n <= 0:
        raise ValueError("n must be positive")
    if bits < 0:
        raise ValueError("bits must be non-negative")
    for weight in range(0, n // 2 + 1):
        if sparse_witness_enumeration_bits(n, weight) >= bits:
            return weight
    return None


def minimum_weight_for_prange_trial_floor(
    n: int,
    k: int,
    bits: float,
) -> int | None:
    """Smallest w <= n-k reaching a requested basic-Prange trial floor."""
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
    """Find the lightest profile passing only the repository's necessary gates."""
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= encryption_error_weight <= n:
        raise ValueError("encryption_error_weight must be in [0, n]")
    if prange_trial_floor_bits < 0:
        raise ValueError("prange_trial_floor_bits must be non-negative")

    secret_weight = minimum_weight_for_prange_trial_floor(
        n,
        k,
        prange_trial_floor_bits,
    )
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
