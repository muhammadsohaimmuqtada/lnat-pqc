"""Fast finite-blocklength simulator for the code-PKE receiver channel.

This module simulates the exact binary observation law seen after the receiver
applies its sparse witness:

    P(Y=1 | X=0) = q
    P(Y=1 | X=1) = 1/2

It avoids constructing full random-code ciphertext words, making rate/reliability
sweeps cheap enough for CI.  The full bridge path remains separately tested.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterable

from code_channel_audit import code_bit_channel_capacity
from code_outer_channel import OuterLinearCode, decode_outer_ml, generate_outer_linear_code


@dataclass(frozen=True)
class FiniteBlocklengthPoint:
    message_bits: int
    channel_uses: int
    trials: int
    failures: int
    channel_capacity_bits_per_use: float

    @property
    def rate(self) -> float:
        return self.message_bits / self.channel_uses

    @property
    def empirical_failure_rate(self) -> float:
        return self.failures / self.trials

    @property
    def capacity_fraction(self) -> float:
        return self.rate / self.channel_capacity_bits_per_use


def sample_channel_observation(
    encoded_word: int,
    outer: OuterLinearCode,
    *,
    zero_one_probability: float,
    rng: random.Random,
) -> int:
    """Sample the receiver observation word for one encoded outer codeword."""
    if not isinstance(encoded_word, int) or not 0 <= encoded_word < (1 << outer.channel_uses):
        raise ValueError("encoded_word is outside the outer-code space")
    if not 0.0 <= zero_one_probability < 0.5:
        raise ValueError("zero_one_probability must be in [0, 0.5)")

    observed = 0
    for index in range(outer.channel_uses):
        transmitted = (encoded_word >> index) & 1
        if transmitted == 1:
            received = rng.getrandbits(1)
        else:
            received = 1 if rng.random() < zero_one_probability else 0
        if received:
            observed |= 1 << index
    return observed


def simulate_outer_code(
    outer: OuterLinearCode,
    *,
    zero_one_probability: float,
    trials: int,
    message_seed: int,
    channel_seed: int,
) -> FiniteBlocklengthPoint:
    if trials <= 0:
        raise ValueError("trials must be positive")
    capacity = code_bit_channel_capacity(zero_one_probability).capacity_bits_per_use
    message_rng = random.Random(message_seed)
    channel_rng = random.Random(channel_seed)
    failures = 0

    for _ in range(trials):
        message = message_rng.randrange(1 << outer.message_bits)
        encoded = outer.encode(message)
        observed = sample_channel_observation(
            encoded,
            outer,
            zero_one_probability=zero_one_probability,
            rng=channel_rng,
        )
        recovered = decode_outer_ml(
            observed,
            outer,
            zero_one_probability=zero_one_probability,
        )
        failures += recovered != message

    return FiniteBlocklengthPoint(
        message_bits=outer.message_bits,
        channel_uses=outer.channel_uses,
        trials=trials,
        failures=failures,
        channel_capacity_bits_per_use=capacity,
    )


def sweep_outer_code_lengths(
    *,
    message_bits: int,
    channel_uses: Iterable[int],
    zero_one_probability: float,
    trials: int,
    code_seed: int = 70_000,
    message_seed: int = 71_000,
    channel_seed: int = 72_000,
) -> tuple[FiniteBlocklengthPoint, ...]:
    lengths = tuple(channel_uses)
    if not lengths:
        raise ValueError("at least one channel length is required")
    if any(length <= message_bits for length in lengths):
        raise ValueError("every channel length must exceed message_bits")

    points = []
    for index, length in enumerate(lengths):
        outer = generate_outer_linear_code(
            message_bits,
            length,
            rng=random.Random(code_seed + index),
        )
        points.append(
            simulate_outer_code(
                outer,
                zero_one_probability=zero_one_probability,
                trials=trials,
                message_seed=message_seed + index,
                channel_seed=channel_seed + index,
            )
        )
    return tuple(points)
