"""Correctness and public-attack audits for code-based research profiles.

This module does not estimate full cryptanalytic security. It reports necessary
checks only:

1. full sparse-witness enumeration size C(n,w);
2. a Prange information-set decoding iteration model, which can be far cheaper;
3. exact decryption-failure probabilities under the reference fixed-weight
   correctness model.

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


def binomial_cdf(trials: int, probability: float, inclusive_max: int) -> float:
    if trials < 0:
        raise ValueError("trials must be non-negative")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")
    if inclusive_max < 0:
        return 0.0
    if inclusive_max >= trials:
        return 1.0
    q = 1.0 - probability
    return math.fsum(
        math.comb(trials, count)
        * (probability**count)
        * (q ** (trials - count))
        for count in range(inclusive_max + 1)
    )


def binomial_tail(trials: int, probability: float, inclusive_min: int) -> float:
    if inclusive_min <= 0:
        return 1.0
    if inclusive_min > trials:
        return 0.0
    return max(0.0, 1.0 - binomial_cdf(trials, probability, inclusive_min - 1))


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

    # In Enc(0), the dual-code contribution is exactly orthogonal to the
    # secret witness. The only remaining inner-product bit comes from the
    # intersection parity of the secret and fresh fixed-weight error supports.
    p_zero_one = fixed_weight_intersection_odd_probability(
        params.n,
        params.secret_weight,
        params.encryption_error_weight,
    )

    # decrypt_bit returns zero iff observed_ones / repetitions < threshold.
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
