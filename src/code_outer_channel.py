"""Toy multi-bit channel coding over the random-code PKE observation channel.

The current research KEM encrypts every seed bit with many independent
repetitions.  This module tests a more efficient direction: encode several
message bits with a small public linear outer code, transmit one random-code
PKE word per outer-code symbol, and maximum-likelihood decode the complete
message from the receiver's inner-product observations.

The decoder enumerates all 2^k messages, so this is deliberately limited to
small k and is NOT a scalable 128-bit KEM construction.  Its purpose is to
show whether the measured channel-capacity headroom can be recovered by code
before investing in a structured decoder such as a polar/LDPC construction.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

from code_pke_reference import (
    BitRNG,
    CodePKEParams,
    CodePKEPublicKey,
    CodePKESecretKey,
    gf2_rank,
    inner_product,
    public_dual_basis,
    random_linear_combination,
    sparse_vector,
)
from code_profile_audit import fixed_weight_intersection_odd_probability
from lnat_code_bridge import (
    LNATCodeBridgePublicKey,
    LNATCodeBridgeSecretKey,
    recover_code_secret,
)

MAX_ML_MESSAGE_BITS = 16


@dataclass(frozen=True)
class OuterLinearCode:
    message_bits: int
    channel_uses: int
    generator_rows: tuple[int, ...]

    def __post_init__(self) -> None:
        if not 0 < self.message_bits <= MAX_ML_MESSAGE_BITS:
            raise ValueError(
                f"message_bits must be in [1, {MAX_ML_MESSAGE_BITS}] for exhaustive ML decoding"
            )
        if self.channel_uses <= self.message_bits:
            raise ValueError("channel_uses must exceed message_bits")
        if len(self.generator_rows) != self.message_bits:
            raise ValueError("generator row count must equal message_bits")
        mask = (1 << self.channel_uses) - 1
        if any(row <= 0 or row > mask for row in self.generator_rows):
            raise ValueError("outer generator row is outside the code space")
        if gf2_rank(self.generator_rows, self.channel_uses) != self.message_bits:
            raise ValueError("outer generator must have full row rank")
        for column in range(self.channel_uses):
            if not any((row >> column) & 1 for row in self.generator_rows):
                raise ValueError("every outer-code coordinate must depend on a message bit")

    @property
    def rate(self) -> float:
        return self.message_bits / self.channel_uses

    def encode(self, message: int) -> int:
        if not isinstance(message, int) or not 0 <= message < (1 << self.message_bits):
            raise ValueError("message is outside the outer-code message space")
        encoded = 0
        for index, row in enumerate(self.generator_rows):
            if (message >> index) & 1:
                encoded ^= row
        return encoded


@dataclass(frozen=True)
class OuterChannelCiphertext:
    words: tuple[int, ...]
    params: CodePKEParams

    def __post_init__(self) -> None:
        mask = (1 << self.params.n) - 1
        if not self.words:
            raise ValueError("outer ciphertext must contain at least one word")
        if any(not isinstance(word, int) or word < 0 or word > mask for word in self.words):
            raise ValueError("outer ciphertext word is outside the code space")

    @property
    def channel_uses(self) -> int:
        return len(self.words)

    def size_bytes(self) -> int:
        return self.channel_uses * ((self.params.n + 7) // 8)


def _rng(rng: BitRNG | None) -> BitRNG:
    return secrets.SystemRandom() if rng is None else rng


def generate_outer_linear_code(
    message_bits: int,
    channel_uses: int,
    *,
    rng: BitRNG | None = None,
) -> OuterLinearCode:
    if not 0 < message_bits <= MAX_ML_MESSAGE_BITS:
        raise ValueError(
            f"message_bits must be in [1, {MAX_ML_MESSAGE_BITS}] for exhaustive ML decoding"
        )
    if channel_uses <= message_bits:
        raise ValueError("channel_uses must exceed message_bits")
    source = _rng(rng)

    for _ in range(10_000):
        rows = tuple(source.getrandbits(channel_uses) for _ in range(message_bits))
        if any(row == 0 for row in rows):
            continue
        if gf2_rank(rows, channel_uses) != message_bits:
            continue
        if any(
            not any((row >> column) & 1 for row in rows)
            for column in range(channel_uses)
        ):
            continue
        return OuterLinearCode(message_bits, channel_uses, rows)
    raise RuntimeError("failed to generate a suitable outer linear code")


def _sample_public_channel_word(
    pk: CodePKEPublicKey,
    symbol: int,
    *,
    dual_basis: tuple[int, ...],
    rng: BitRNG,
) -> int:
    if symbol == 1:
        return rng.getrandbits(pk.params.n)
    if symbol != 0:
        raise ValueError("outer channel symbol must be 0 or 1")
    dual_word = random_linear_combination(dual_basis, rng=rng)
    error = sparse_vector(
        pk.params.n,
        pk.params.encryption_error_weight,
        rng=rng,
    )
    return dual_word ^ error


def encrypt_outer_message(
    pk: CodePKEPublicKey,
    outer: OuterLinearCode,
    message: int,
    *,
    rng: BitRNG | None = None,
) -> OuterChannelCiphertext:
    """Transmit one public random-code word per outer-code symbol."""
    source = _rng(rng)
    encoded = outer.encode(message)
    dual_basis = public_dual_basis(pk)
    words = tuple(
        _sample_public_channel_word(
            pk,
            (encoded >> index) & 1,
            dual_basis=dual_basis,
            rng=source,
        )
        for index in range(outer.channel_uses)
    )
    return OuterChannelCiphertext(words, pk.params)


def observe_outer_ciphertext(
    sk: CodePKESecretKey,
    ct: OuterChannelCiphertext,
) -> int:
    if sk.params != ct.params:
        raise ValueError("parameter mismatch")
    observed = 0
    for index, word in enumerate(ct.words):
        if inner_product(word, sk.error):
            observed |= 1 << index
    return observed


def _log_probability(observed_bit: int, encoded_bit: int, q: float) -> float:
    if encoded_bit == 1:
        return math.log(0.5)
    probability = q if observed_bit else 1.0 - q
    if probability == 0.0:
        return -math.inf
    return math.log(probability)


def decode_outer_ml(
    observed: int,
    outer: OuterLinearCode,
    *,
    zero_one_probability: float,
) -> int:
    """Maximum-likelihood decode by enumerating the tiny outer message space."""
    if not isinstance(observed, int) or not 0 <= observed < (1 << outer.channel_uses):
        raise ValueError("observed word is outside the outer-code space")
    if not 0.0 <= zero_one_probability < 0.5:
        raise ValueError("zero_one_probability must be in [0, 0.5)")

    best_message = 0
    best_log_likelihood = -math.inf
    for message in range(1 << outer.message_bits):
        encoded = outer.encode(message)
        log_likelihood = 0.0
        for index in range(outer.channel_uses):
            log_likelihood += _log_probability(
                (observed >> index) & 1,
                (encoded >> index) & 1,
                zero_one_probability,
            )
        if log_likelihood > best_log_likelihood:
            best_log_likelihood = log_likelihood
            best_message = message
    return best_message


def decrypt_outer_message(
    sk: CodePKESecretKey,
    ct: OuterChannelCiphertext,
    outer: OuterLinearCode,
) -> int:
    if ct.channel_uses != outer.channel_uses:
        raise ValueError("outer ciphertext length does not match outer code")
    observed = observe_outer_ciphertext(sk, ct)
    q = fixed_weight_intersection_odd_probability(
        sk.params.n,
        sk.params.secret_weight,
        sk.params.encryption_error_weight,
    )
    return decode_outer_ml(
        observed,
        outer,
        zero_one_probability=q,
    )


def encrypt_bridge_outer_message(
    pk: LNATCodeBridgePublicKey,
    outer: OuterLinearCode,
    message: int,
    *,
    rng: BitRNG | None = None,
) -> OuterChannelCiphertext:
    """Public-only bridge encryption of a small multi-bit message."""
    return encrypt_outer_message(pk.code_key, outer, message, rng=rng)


def decrypt_bridge_outer_message(
    sk: LNATCodeBridgeSecretKey,
    pk: LNATCodeBridgePublicKey,
    ct: OuterChannelCiphertext,
    outer: OuterLinearCode,
) -> int:
    code_secret = recover_code_secret(sk, pk)
    return decrypt_outer_message(code_secret, ct, outer)
