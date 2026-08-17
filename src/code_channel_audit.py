"""Efficiency audit for the binary channel induced by the code-PKE comparator.

For one public code-PKE word, the receiver observes the inner-product bit with
the sparse witness. Under the reference model:

* transmitted 0 -> Bernoulli(q), where q is the odd support-intersection rate;
* transmitted 1 -> Bernoulli(1/2).

That is a binary-input/binary-output asymmetric channel.  This module computes
its Shannon capacity and compares the current bit-by-bit repetition KEM against
a capacity-only lower bound on channel uses/ciphertext bytes.

Capacity is an engineering lower bound, not an achievable finite-blocklength
construction and not a security claim.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_pke_reference import CodePKEParams
from code_profile_audit import fixed_weight_intersection_odd_probability


@dataclass(frozen=True)
class BinaryHypothesisChannelAudit:
    zero_one_probability: float
    one_one_probability: float
    capacity_bits_per_use: float
    optimal_input_one_probability: float
    output_one_probability_at_capacity: float


@dataclass(frozen=True)
class RepetitionEfficiencyAudit:
    params: CodePKEParams
    message_bits: int
    confirmation_tag_bytes: int
    channel: BinaryHypothesisChannelAudit
    word_bytes: int
    repetition_channel_uses: int
    capacity_lower_bound_channel_uses: int
    repetition_ciphertext_bytes: int
    capacity_lower_bound_ciphertext_bytes: int

    @property
    def channel_use_overhead_ratio(self) -> float:
        return self.repetition_channel_uses / self.capacity_lower_bound_channel_uses

    @property
    def ciphertext_overhead_ratio(self) -> float:
        return self.repetition_ciphertext_bytes / self.capacity_lower_bound_ciphertext_bytes


def binary_entropy(probability: float) -> float:
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")
    if probability in (0.0, 1.0):
        return 0.0
    return -probability * math.log2(probability) - (1.0 - probability) * math.log2(
        1.0 - probability
    )


def code_bit_channel_capacity(zero_one_probability: float) -> BinaryHypothesisChannelAudit:
    """Capacity for P(Y=1|X=0)=q and P(Y=1|X=1)=1/2.

    The maximizing output-one probability follows from setting dI/dP(X=1)=0.
    Boundary candidates are checked as well for numerical robustness.
    """
    q = zero_one_probability
    if not 0.0 <= q < 0.5:
        raise ValueError("zero_one_probability must be in [0, 0.5)")

    hq = binary_entropy(q)
    delta = 0.5 - q
    log_odds_target = (1.0 - hq) / delta
    output_one = 1.0 / (1.0 + 2.0**log_odds_target)
    input_one = (output_one - q) / delta
    input_one = min(1.0, max(0.0, input_one))
    output_one = q + input_one * delta

    def mutual_information(p_one: float) -> float:
        py1 = q + p_one * delta
        return binary_entropy(py1) - (1.0 - p_one) * hq - p_one

    candidates = ((mutual_information(0.0), 0.0), (mutual_information(1.0), 1.0), (mutual_information(input_one), input_one))
    capacity, best_input = max(candidates, key=lambda pair: pair[0])
    best_output = q + best_input * delta

    return BinaryHypothesisChannelAudit(
        zero_one_probability=q,
        one_one_probability=0.5,
        capacity_bits_per_use=max(0.0, capacity),
        optimal_input_one_probability=best_input,
        output_one_probability_at_capacity=best_output,
    )


def minimum_channel_uses_by_capacity(message_bits: int, capacity_bits_per_use: float) -> int:
    if message_bits <= 0:
        raise ValueError("message_bits must be positive")
    if not 0.0 < capacity_bits_per_use <= 1.0:
        raise ValueError("capacity_bits_per_use must be in (0, 1]")
    return math.ceil(message_bits / capacity_bits_per_use)


def audit_repetition_efficiency(
    params: CodePKEParams,
    *,
    message_bits: int,
    confirmation_tag_bytes: int = 16,
) -> RepetitionEfficiencyAudit:
    if message_bits <= 0:
        raise ValueError("message_bits must be positive")
    if confirmation_tag_bytes < 0:
        raise ValueError("confirmation_tag_bytes must be non-negative")

    q = fixed_weight_intersection_odd_probability(
        params.n,
        params.secret_weight,
        params.encryption_error_weight,
    )
    channel = code_bit_channel_capacity(q)
    if channel.capacity_bits_per_use <= 0.0:
        raise ValueError("reference channel has zero capacity")

    word_bytes = (params.n + 7) // 8
    repetition_uses = message_bits * params.repetitions
    lower_uses = minimum_channel_uses_by_capacity(
        message_bits,
        channel.capacity_bits_per_use,
    )
    repetition_bytes = repetition_uses * word_bytes + confirmation_tag_bytes
    lower_bytes = lower_uses * word_bytes + confirmation_tag_bytes

    return RepetitionEfficiencyAudit(
        params=params,
        message_bits=message_bits,
        confirmation_tag_bytes=confirmation_tag_bytes,
        channel=channel,
        word_bytes=word_bytes,
        repetition_channel_uses=repetition_uses,
        capacity_lower_bound_channel_uses=lower_uses,
        repetition_ciphertext_bytes=repetition_bytes,
        capacity_lower_bound_ciphertext_bytes=lower_bytes,
    )
