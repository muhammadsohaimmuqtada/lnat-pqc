"""Executable Stern-style collision information-set decoding baseline.

This module strengthens the public syndrome-decoding attack model beyond
Prange/Lee-Brickell for reduced binary random-code profiles. It implements a
meet-in-the-middle collision step inside a sampled systematic information set:

* choose parity positions J of size r=n-k and require H_J to be invertible;
* transform the target syndrome and information-set columns through H_J^-1;
* split the k information positions into two halves;
* enumerate weight-p subsets in each half;
* collide their transformed partial syndromes on l selected parity bits; and
* test whether the remaining parity vector has weight w-2p.

The implementation is intended for executable reduced-parameter validation.
The cost model is deliberately transparent and omits the probability that a
sampled H_J is invertible. It is NOT a security proof or a modern optimized ISD
estimator.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from itertools import combinations

from code_isd import (
    _column_syndrome,
    _expand_positions,
    _invert_square_gf2,
    _pack_syndrome,
    _restrict_row,
    _solve_with_inverse,
)
from code_pke_reference import BitRNG, CodePKEPublicKey, inner_product, nullspace_basis


@dataclass(frozen=True)
class SternRecoveryResult:
    witness: int
    p: int
    l: int
    information_sets_sampled: int
    invertible_information_sets: int
    left_list_entries: int
    right_list_entries: int
    collision_candidates_tested: int


@dataclass(frozen=True)
class SternCostPoint:
    n: int
    k: int
    weight: int
    p: int
    l: int
    success_probability_per_information_set: float
    expected_information_sets: float
    left_list_size: int
    right_list_size: int
    expected_collisions_per_invertible_set: float
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


def _validate_stern_parameters(n: int, k: int, weight: int, p: int, l: int) -> None:
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    if p <= 0:
        raise ValueError("p must be positive for Stern collision search")
    if 2 * p > weight:
        raise ValueError("2*p cannot exceed the target weight")
    r = n - k
    if not 0 < l <= r:
        raise ValueError("l must be in [1, n-k]")
    if weight - 2 * p > r - l:
        raise ValueError("remaining error weight does not fit outside collision coordinates")
    left = k // 2
    right = k - left
    if p > left or p > right:
        raise ValueError("p does not fit both information-set halves")


def stern_success_probability(n: int, k: int, weight: int, p: int, l: int) -> float:
    """Combinatorial useful-set probability for the implemented Stern event.

    The event requires p errors in each information-set half, zero errors in
    the l collision-filter parity coordinates, and w-2p errors in the other
    parity coordinates. The probability that H_J is invertible is intentionally
    excluded and is measured by the executable attack instead.
    """
    _validate_stern_parameters(n, k, weight, p, l)
    r = n - k
    left = k // 2
    right = k - left
    return (
        math.comb(left, p)
        * math.comb(right, p)
        * math.comb(r - l, weight - 2 * p)
        / math.comb(n, weight)
    )


def stern_cost_point(n: int, k: int, weight: int, p: int, l: int) -> SternCostPoint:
    """Transparent operation/memory model for one Stern collision point."""
    probability = stern_success_probability(n, k, weight, p, l)
    r = n - k
    left = k // 2
    right = k - left
    left_size = math.comb(left, p)
    right_size = math.comb(right, p)
    expected_collisions = left_size * right_size / (2**l)

    elimination = r**3
    list_ops = (left_size + right_size) * p * r
    collision_ops = expected_collisions * r
    per_set = elimination + list_ops + collision_ops
    expected_sets = math.inf if probability == 0 else 1.0 / probability
    estimated_total = math.inf if probability == 0 else expected_sets * per_set

    return SternCostPoint(
        n=n,
        k=k,
        weight=weight,
        p=p,
        l=l,
        success_probability_per_information_set=probability,
        expected_information_sets=expected_sets,
        left_list_size=left_size,
        right_list_size=right_size,
        expected_collisions_per_invertible_set=expected_collisions,
        elimination_ops_per_set=elimination,
        list_ops_per_set=list_ops,
        collision_ops_per_set=collision_ops,
        estimated_total_ops=estimated_total,
        estimated_memory_entries=left_size,
    )


def best_stern_cost(
    n: int,
    k: int,
    weight: int,
    *,
    max_p: int = 4,
    max_l: int = 32,
) -> SternCostPoint:
    if max_p <= 0:
        raise ValueError("max_p must be positive")
    if max_l <= 0:
        raise ValueError("max_l must be positive")
    points: list[SternCostPoint] = []
    upper_p = min(max_p, weight // 2, k // 2, k - k // 2)
    for p in range(1, upper_p + 1):
        r = n - k
        upper_l = min(max_l, r - (weight - 2 * p))
        for l in range(1, upper_l + 1):
            try:
                points.append(stern_cost_point(n, k, weight, p, l))
            except ValueError:
                continue
    if not points:
        raise ValueError("no valid Stern parameter points")
    return min(points, key=lambda point: point.estimated_total_ops)


def _subset_sum(
    positions: tuple[int, ...],
    transformed_columns: dict[int, int],
) -> tuple[int, int]:
    value = 0
    bits = 0
    for position in positions:
        value ^= transformed_columns[position]
        bits |= 1 << position
    return value, bits


def recover_sparse_error_stern(
    pk: CodePKEPublicKey,
    *,
    p: int,
    l: int,
    rng: BitRNG | None = None,
    max_information_sets: int = 10_000,
) -> SternRecoveryResult:
    """Recover a sparse public witness using Stern-style collision lists.

    The collision coordinates are the low l coordinates of the transformed
    parity solution. For a useful sampled information set, the real residual
    error is zero on those coordinates, so left/right partial sums must collide
    against the transformed target projection.
    """
    if max_information_sets <= 0:
        raise ValueError("max_information_sets must be positive")
    params = pk.params
    _validate_stern_parameters(params.n, params.k, params.secret_weight, p, l)

    source = secrets.SystemRandom() if rng is None else rng
    r = params.n - params.k
    parity_checks = nullspace_basis(pk.generator, params.n)
    if len(parity_checks) != r:
        raise ValueError("public parity-check basis has unexpected dimension")

    target = _pack_syndrome(
        tuple(inner_product(row, pk.noisy_codeword) for row in parity_checks)
    )
    column_syndromes = tuple(
        _column_syndrome(parity_checks, position)
        for position in range(params.n)
    )
    all_positions = tuple(range(params.n))
    invertible_sets = 0
    left_entries_total = 0
    right_entries_total = 0
    collision_candidates = 0

    for sampled in range(1, max_information_sets + 1):
        parity_positions = tuple(sorted(source.sample(range(params.n), r)))
        parity_lookup = set(parity_positions)
        information_positions = tuple(
            position for position in all_positions if position not in parity_lookup
        )

        restricted_rows = tuple(
            _restrict_row(row, parity_positions) for row in parity_checks
        )
        inverse = _invert_square_gf2(restricted_rows, r)
        if inverse is None:
            continue
        invertible_sets += 1

        transformed_target = _solve_with_inverse(inverse, target)
        transformed_columns = {
            position: _solve_with_inverse(inverse, column_syndromes[position])
            for position in information_positions
        }
        split = len(information_positions) // 2
        left_positions = information_positions[:split]
        right_positions = information_positions[split:]
        projection_mask = (1 << l) - 1

        buckets: dict[int, list[tuple[int, int]]] = {}
        for guessed in combinations(left_positions, p):
            partial, info_bits = _subset_sum(guessed, transformed_columns)
            buckets.setdefault(partial & projection_mask, []).append((partial, info_bits))
            left_entries_total += 1

        for guessed in combinations(right_positions, p):
            right_partial, right_bits = _subset_sum(guessed, transformed_columns)
            right_entries_total += 1
            wanted = (transformed_target ^ right_partial) & projection_mask
            for left_partial, left_bits in buckets.get(wanted, ()):
                collision_candidates += 1
                parity_local = transformed_target ^ left_partial ^ right_partial
                if parity_local.bit_count() != params.secret_weight - 2 * p:
                    continue
                candidate = left_bits | right_bits | _expand_positions(
                    parity_local, parity_positions
                )
                if candidate.bit_count() != params.secret_weight:
                    continue
                syndrome = _pack_syndrome(
                    tuple(inner_product(row, candidate) for row in parity_checks)
                )
                if syndrome == target:
                    return SternRecoveryResult(
                        witness=candidate,
                        p=p,
                        l=l,
                        information_sets_sampled=sampled,
                        invertible_information_sets=invertible_sets,
                        left_list_entries=left_entries_total,
                        right_list_entries=right_entries_total,
                        collision_candidates_tested=collision_candidates,
                    )

    raise ValueError("Stern attack did not find a sparse witness within the limit")
