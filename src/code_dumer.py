"""Executable Dumer-style enlarged-information-set decoding baseline.

This module implements the next collision/list step beyond the repository's
Stern baseline for reduced binary random-code profiles.

For parity dimension r=n-k and a chosen extension l:

* select J of size r-l and let I be its complement of size k+l;
* row-reduce H_J to [I_{r-l}; 0_l];
* split I into two halves;
* enumerate weight-p/2 subsets in each half;
* collide the two lists on the bottom l transformed syndrome coordinates; and
* solve the remaining J coordinates directly from the top r-l coordinates.

The implementation is a research attack baseline, not a production decoder.
Its cost model is intentionally transparent and omits optimized list generation,
bit-slicing, cache effects, and later MMT/BJMM representation techniques.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from itertools import combinations

from code_isd import _column_syndrome, _expand_positions, _pack_syndrome
from code_pke_reference import BitRNG, CodePKEPublicKey, inner_product, nullspace_basis, parity


@dataclass(frozen=True)
class DumerRecoveryResult:
    witness: int
    p: int
    l: int
    information_sets_sampled: int
    systematic_information_sets: int
    left_list_entries: int
    right_list_entries: int
    collision_candidates_tested: int


@dataclass(frozen=True)
class DumerCostPoint:
    n: int
    k: int
    weight: int
    p: int
    l: int
    success_probability_per_information_set: float
    expected_information_sets: float
    left_list_size: int
    right_list_size: int
    expected_collisions_per_systematic_set: float
    elimination_ops_per_set: int
    list_ops_per_set: int
    collision_ops_per_set: float
    estimated_total_ops: float
    estimated_memory_entries: int

    @property
    def expected_information_set_bits(self) -> float:
        return math.log2(self.expected_information_sets)

    @property
    def estimated_total_ops_bits(self) -> float:
        return math.log2(self.estimated_total_ops)

    @property
    def estimated_memory_bits(self) -> float:
        return math.log2(max(1, self.estimated_memory_entries))


def _validate_parameters(n: int, k: int, weight: int, p: int, l: int) -> None:
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    if p <= 0 or p & 1:
        raise ValueError("p must be a positive even integer")
    if p > weight:
        raise ValueError("p cannot exceed target weight")
    r = n - k
    if not 0 < l < r:
        raise ValueError("l must be in [1, n-k-1]")
    if weight - p > r - l:
        raise ValueError("remaining error weight does not fit outside enlarged information set")
    info = k + l
    left = info // 2
    right = info - left
    half_weight = p // 2
    if half_weight > left or half_weight > right:
        raise ValueError("p/2 does not fit both information-set halves")


def dumer_success_probability(n: int, k: int, weight: int, p: int, l: int) -> float:
    """Exact split-event probability for the implemented Dumer iteration."""
    _validate_parameters(n, k, weight, p, l)
    r = n - k
    info = k + l
    left = info // 2
    right = info - left
    half_weight = p // 2
    return (
        math.comb(left, half_weight)
        * math.comb(right, half_weight)
        * math.comb(r - l, weight - p)
        / math.comb(n, weight)
    )


def dumer_cost_point(n: int, k: int, weight: int, p: int, l: int) -> DumerCostPoint:
    probability = dumer_success_probability(n, k, weight, p, l)
    r = n - k
    info = k + l
    left = info // 2
    right = info - left
    half_weight = p // 2
    left_size = math.comb(left, half_weight)
    right_size = math.comb(right, half_weight)
    expected_collisions = left_size * right_size / (2**l)

    elimination = r**3
    list_ops = (left_size + right_size) * max(1, half_weight) * r
    collision_ops = expected_collisions * r
    per_set = elimination + list_ops + collision_ops
    expected_sets = math.inf if probability == 0 else 1.0 / probability
    total = math.inf if probability == 0 else expected_sets * per_set

    return DumerCostPoint(
        n=n,
        k=k,
        weight=weight,
        p=p,
        l=l,
        success_probability_per_information_set=probability,
        expected_information_sets=expected_sets,
        left_list_size=left_size,
        right_list_size=right_size,
        expected_collisions_per_systematic_set=expected_collisions,
        elimination_ops_per_set=elimination,
        list_ops_per_set=list_ops,
        collision_ops_per_set=collision_ops,
        estimated_total_ops=total,
        estimated_memory_entries=left_size,
    )


def best_dumer_cost(
    n: int,
    k: int,
    weight: int,
    *,
    max_p: int = 8,
    max_l: int = 32,
) -> DumerCostPoint:
    if max_p < 2:
        raise ValueError("max_p must be at least 2")
    if max_l <= 0:
        raise ValueError("max_l must be positive")
    points: list[DumerCostPoint] = []
    upper_p = min(max_p, weight)
    upper_l = min(max_l, n - k - 1)
    for p in range(2, upper_p + 1, 2):
        for l in range(1, upper_l + 1):
            try:
                points.append(dumer_cost_point(n, k, weight, p, l))
            except ValueError:
                continue
    if not points:
        raise ValueError("no valid Dumer parameter points")
    return min(points, key=lambda point: point.estimated_total_ops)


def _restrict_columns(row: int, positions: tuple[int, ...]) -> int:
    value = 0
    for local, position in enumerate(positions):
        if (row >> position) & 1:
            value |= 1 << local
    return value


def _systematic_transform(
    parity_checks: tuple[int, ...],
    selected_positions: tuple[int, ...],
) -> tuple[int, ...] | None:
    """Return row-combination masks U with U*H_J = [I;0], or None.

    Each returned integer is a mask selecting/xoring original parity-check rows.
    The first |J| transformed rows form the identity on J; remaining rows vanish
    on J and therefore provide the l collision equations.
    """
    row_count = len(parity_checks)
    column_count = len(selected_positions)
    work = [_restrict_columns(row, selected_positions) for row in parity_checks]
    transforms = [1 << index for index in range(row_count)]

    pivot_row = 0
    for column in range(column_count):
        selected = next(
            (index for index in range(pivot_row, row_count) if (work[index] >> column) & 1),
            None,
        )
        if selected is None:
            return None
        work[pivot_row], work[selected] = work[selected], work[pivot_row]
        transforms[pivot_row], transforms[selected] = transforms[selected], transforms[pivot_row]
        pivot = work[pivot_row]
        transform = transforms[pivot_row]
        for index in range(row_count):
            if index != pivot_row and ((work[index] >> column) & 1):
                work[index] ^= pivot
                transforms[index] ^= transform
        pivot_row += 1

    identity_mask = (1 << column_count) - 1
    for index in range(column_count):
        if work[index] != (1 << index):
            return None
    if any(work[index] != 0 for index in range(column_count, row_count)):
        return None
    if identity_mask and column_count == 0:
        return None
    return tuple(transforms)


def _apply_transform(transform_rows: tuple[int, ...], syndrome: int) -> int:
    value = 0
    for output_bit, row_mask in enumerate(transform_rows):
        if parity(row_mask & syndrome):
            value |= 1 << output_bit
    return value


def _subset_sum(
    positions: tuple[int, ...],
    transformed_columns: dict[int, int],
) -> tuple[int, int]:
    syndrome = 0
    vector = 0
    for position in positions:
        syndrome ^= transformed_columns[position]
        vector |= 1 << position
    return syndrome, vector


def recover_sparse_error_dumer(
    pk: CodePKEPublicKey,
    *,
    p: int,
    l: int,
    rng: BitRNG | None = None,
    max_information_sets: int = 10_000,
) -> DumerRecoveryResult:
    """Recover a valid sparse public witness with enlarged-set collisions."""
    if max_information_sets <= 0:
        raise ValueError("max_information_sets must be positive")
    params = pk.params
    _validate_parameters(params.n, params.k, params.secret_weight, p, l)
    source = secrets.SystemRandom() if rng is None else rng

    r = params.n - params.k
    selected_count = r - l
    parity_checks = nullspace_basis(pk.generator, params.n)
    if len(parity_checks) != r:
        raise ValueError("public parity-check basis has unexpected dimension")
    target = _pack_syndrome(
        tuple(inner_product(row, pk.noisy_codeword) for row in parity_checks)
    )
    columns = tuple(
        _column_syndrome(parity_checks, position)
        for position in range(params.n)
    )
    all_positions = tuple(range(params.n))
    half_weight = p // 2
    systematic_sets = 0
    left_entries_total = 0
    right_entries_total = 0
    collision_candidates = 0

    for sampled in range(1, max_information_sets + 1):
        selected_positions = tuple(sorted(source.sample(range(params.n), selected_count)))
        selected_lookup = set(selected_positions)
        information_positions = tuple(
            position for position in all_positions if position not in selected_lookup
        )
        transform_rows = _systematic_transform(parity_checks, selected_positions)
        if transform_rows is None:
            continue
        systematic_sets += 1

        transformed_target = _apply_transform(transform_rows, target)
        transformed_columns = {
            position: _apply_transform(transform_rows, columns[position])
            for position in information_positions
        }
        split = len(information_positions) // 2
        left_positions = information_positions[:split]
        right_positions = information_positions[split:]
        bottom_mask = ((1 << l) - 1) << selected_count

        buckets: dict[int, list[tuple[int, int]]] = {}
        for guessed in combinations(left_positions, half_weight):
            partial, bits = _subset_sum(guessed, transformed_columns)
            buckets.setdefault(partial & bottom_mask, []).append((partial, bits))
            left_entries_total += 1

        target_bottom = transformed_target & bottom_mask
        for guessed in combinations(right_positions, half_weight):
            right_partial, right_bits = _subset_sum(guessed, transformed_columns)
            right_entries_total += 1
            wanted = target_bottom ^ (right_partial & bottom_mask)
            for left_partial, left_bits in buckets.get(wanted, ()):
                collision_candidates += 1
                residual = transformed_target ^ left_partial ^ right_partial
                if residual & bottom_mask:
                    continue
                selected_local = residual & ((1 << selected_count) - 1)
                if selected_local.bit_count() != params.secret_weight - p:
                    continue
                candidate = left_bits | right_bits | _expand_positions(
                    selected_local,
                    selected_positions,
                )
                if candidate.bit_count() != params.secret_weight:
                    continue
                syndrome = _pack_syndrome(
                    tuple(inner_product(row, candidate) for row in parity_checks)
                )
                if syndrome == target:
                    return DumerRecoveryResult(
                        witness=candidate,
                        p=p,
                        l=l,
                        information_sets_sampled=sampled,
                        systematic_information_sets=systematic_sets,
                        left_list_entries=left_entries_total,
                        right_list_entries=right_entries_total,
                        collision_candidates_tested=collision_candidates,
                    )

    raise ValueError("Dumer attack did not find a sparse witness within the limit")
