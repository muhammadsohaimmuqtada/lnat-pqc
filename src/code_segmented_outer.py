"""Segmented small-message outer coding over the random-code receiver channel.

A 128-bit KEM seed cannot be maximum-likelihood decoded as one random linear
block because exhaustive ML would require 2^128 message candidates. This
module keeps the decoder scalable for research by splitting the message into
small independent blocks (currently bytes) and ML-decoding each block.

The construction changes efficiency/correctness only. Public-key security
remains the random-code decoding problem exposed by the bridge.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from code_outer_channel import OuterChannelCiphertext, OuterLinearCode, decode_outer_ml, generate_outer_linear_code
from code_pke_reference import (
    BitRNG,
    CodePKEParams,
    CodePKEPublicKey,
    CodePKESecretKey,
    inner_product,
    public_dual_basis,
    random_linear_combination,
    sparse_vector,
)
from code_profile_audit import fixed_weight_intersection_odd_probability


@dataclass(frozen=True)
class SegmentedOuterCode:
    blocks: tuple[OuterLinearCode, ...]

    def __post_init__(self) -> None:
        if not self.blocks:
            raise ValueError("segmented outer code must contain at least one block")
        if any(block.message_bits != 8 for block in self.blocks):
            raise ValueError("current segmented outer code requires 8-bit blocks")
        channel_uses = self.blocks[0].channel_uses
        if any(block.channel_uses != channel_uses for block in self.blocks):
            raise ValueError("all segmented blocks must use the same channel length")

    @property
    def message_bytes(self) -> int:
        return len(self.blocks)

    @property
    def channel_uses_per_byte(self) -> int:
        return self.blocks[0].channel_uses

    @property
    def total_channel_uses(self) -> int:
        return self.message_bytes * self.channel_uses_per_byte


@dataclass(frozen=True)
class SegmentedOuterCiphertext:
    blocks: tuple[OuterChannelCiphertext, ...]
    params: CodePKEParams

    def __post_init__(self) -> None:
        if not self.blocks:
            raise ValueError("segmented ciphertext must contain at least one block")
        if any(block.params != self.params for block in self.blocks):
            raise ValueError("segmented ciphertext parameter mismatch")

    @property
    def message_bytes(self) -> int:
        return len(self.blocks)

    @property
    def total_channel_uses(self) -> int:
        return sum(block.channel_uses for block in self.blocks)

    def size_bytes(self) -> int:
        return sum(block.size_bytes() for block in self.blocks)


def _rng(rng: BitRNG | None) -> BitRNG:
    return secrets.SystemRandom() if rng is None else rng


def generate_segmented_outer_code(
    message_bytes: int,
    channel_uses_per_byte: int,
    *,
    rng: BitRNG | None = None,
) -> SegmentedOuterCode:
    if message_bytes <= 0:
        raise ValueError("message_bytes must be positive")
    source = _rng(rng)
    blocks = tuple(
        generate_outer_linear_code(8, channel_uses_per_byte, rng=source)
        for _ in range(message_bytes)
    )
    return SegmentedOuterCode(blocks)


def _sample_symbol(
    pk: CodePKEPublicKey,
    symbol: int,
    *,
    dual_basis: tuple[int, ...],
    rng: BitRNG,
) -> int:
    if symbol == 1:
        return rng.getrandbits(pk.params.n)
    if symbol != 0:
        raise ValueError("outer symbol must be 0 or 1")
    dual_word = random_linear_combination(dual_basis, rng=rng)
    error = sparse_vector(
        pk.params.n,
        pk.params.encryption_error_weight,
        rng=rng,
    )
    return dual_word ^ error


def encrypt_segmented_message(
    pk: CodePKEPublicKey,
    outer: SegmentedOuterCode,
    message: bytes,
    *,
    rng: BitRNG | None = None,
) -> SegmentedOuterCiphertext:
    """Publicly encrypt bytes with one cached public dual basis."""
    if len(message) != outer.message_bytes:
        raise ValueError("message length does not match segmented outer code")
    source = _rng(rng)
    dual_basis = public_dual_basis(pk)
    ciphertext_blocks = []

    for value, block in zip(message, outer.blocks):
        encoded = block.encode(value)
        words = tuple(
            _sample_symbol(
                pk,
                (encoded >> index) & 1,
                dual_basis=dual_basis,
                rng=source,
            )
            for index in range(block.channel_uses)
        )
        ciphertext_blocks.append(OuterChannelCiphertext(words, pk.params))

    return SegmentedOuterCiphertext(tuple(ciphertext_blocks), pk.params)


def decrypt_segmented_message(
    sk: CodePKESecretKey,
    ct: SegmentedOuterCiphertext,
    outer: SegmentedOuterCode,
) -> bytes:
    if sk.params != ct.params:
        raise ValueError("parameter mismatch")
    if ct.message_bytes != outer.message_bytes:
        raise ValueError("ciphertext block count does not match outer code")

    q = fixed_weight_intersection_odd_probability(
        sk.params.n,
        sk.params.secret_weight,
        sk.params.encryption_error_weight,
    )
    decoded = bytearray()
    for ciphertext_block, code_block in zip(ct.blocks, outer.blocks):
        if ciphertext_block.channel_uses != code_block.channel_uses:
            raise ValueError("ciphertext block length does not match outer code")
        observed = 0
        for index, word in enumerate(ciphertext_block.words):
            if inner_product(word, sk.error):
                observed |= 1 << index
        decoded.append(
            decode_outer_ml(
                observed,
                code_block,
                zero_one_probability=q,
            )
        )
    return bytes(decoded)
