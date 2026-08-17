"""Executable generalized information-set decoding for research profiles.

This module adds a Lee-Brickell-style extension of the existing Prange attack.
It is intentionally explicit rather than claiming a modern ISD security level:

* choose an information set I of size k and parity set J of size n-k;
* require the public parity-check submatrix H_J to be invertible;
* guess exactly p error positions inside I;
* solve the remaining syndrome uniquely on J; and
* accept when the complete candidate has the advertised Hamming weight.

p=0 is Prange.  p>0 trades more cheap guesses inside an information set for
fewer expensive information-set changes / matrix eliminations.

The accompanying cost model counts a naive GF(2) elimination term and a simple
per-guess term.  It is a transparent implementation model, NOT a security-bit
claim and NOT a substitute for Stern/Dumer/BJMM-style estimates.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from itertools import combinations

from code_pke_reference import BitRNG, CodePKEPublicKey, inner_product, nullspace_basis


@dataclass(frozen=True)
class LeeBrickellRecoveryResult:
    witness: int
    p: int
    information_sets_sampled: int
    invertible_information_sets: int
    guesses_tested: int


@dataclass(frozen=True)
class LeeBrickellCostPoint:
    n: int
    k: int
    weight: int
    p: int
    success_probability_per_information_set: float
    expected_information_sets: float
    guesses_per_invertible_set: int
    elimination_ops_per_set: int
    guess_ops_per_set: int
    estimated_total_ops: float

    @property
    def expected_information_set_bits(self) -> float:
        return math.log2(self.expected_information_sets)

    @property
    def estimated_total_ops_bits(self) -> float:
        return math.log2(self.estimated_total_ops)


def _pack_syndrome(bits: tuple[int, ...]) -> int:
    packed = 0
    for index, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("syndrome bits must be binary")
        packed |= bit << index
    return packed


def _column_syndrome(parity_checks: tuple[int, ...], position: int) -> int:
    packed = 0
    for row_index, row in enumerate(parity_checks):
        packed |= ((row >> position) & 1) << row_index
    return packed


def _restrict_row(row: int, positions: tuple[int, ...]) -> int:
    compressed = 0
    for local, absolute in enumerate(positions):
        compressed |= ((row >> absolute) & 1) << local
    return compressed


def _invert_square_gf2(rows: tuple[int, ...], size: int) -> tuple[int, ...] | None:
    """Return row representation of A^-1 for a binary square matrix A."""
    if size <= 0 or len(rows) != size:
        raise ValueError("square matrix dimensions do not match")
    mask = (1 << size) - 1
    if any(row < 0 or row > mask for row in rows):
        raise ValueError("matrix row is outside the square matrix width")

    augmented = [row | (1 << (size + index)) for index, row in enumerate(rows)]
    pivot_row = 0
    for column in range(size):
        selected = next(
            (
                index
                for index in range(pivot_row, size)
                if (augmented[index] >> column) & 1
            ),
            None,
        )
        if selected is None:
            return None
        augmented[pivot_row], augmented[selected] = (
            augmented[selected],
            augmented[pivot_row],
        )
        pivot = augmented[pivot_row]
        for index in range(size):
            if index != pivot_row and ((augmented[index] >> column) & 1):
                augmented[index] ^= pivot
        pivot_row += 1

    for index, row in enumerate(augmented):
        if (row & mask) != (1 << index):
            raise RuntimeError("GF(2) inversion failed to produce identity")
    return tuple(row >> size for row in augmented)


def _solve_with_inverse(inverse_rows: tuple[int, ...], rhs: int) -> int:
    solution = 0
    for index, row in enumerate(inverse_rows):
        if (row & rhs).bit_count() & 1:
            solution |= 1 << index
    return solution


def _expand_positions(local_bits: int, positions: tuple[int, ...]) -> int:
    expanded = 0
    for local, absolute in enumerate(positions):
        if (local_bits >> local) & 1:
            expanded |= 1 << absolute
    return expanded


def lee_brickell_success_probability(n: int, k: int, weight: int, p: int) -> float:
    """Probability a random size-k information set contains exactly p errors.

    This ignores the additional probability that the selected H_J submatrix is
    invertible.  The executable attack reports invertible-set counts directly.
    """
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    if not 0 <= p <= min(k, weight):
        raise ValueError("p is outside the possible information-set error count")
    parity_size = n - k
    if weight - p < 0 or weight - p > parity_size:
        return 0.0
    return (
        math.comb(k, p)
        * math.comb(parity_size, weight - p)
        / math.comb(n, weight)
    )


def lee_brickell_cost_point(n: int, k: int, weight: int, p: int) -> LeeBrickellCostPoint:
    """Transparent naive operation model for one Lee-Brickell parameter p.

    Elimination is modeled as (n-k)^3 binary operations per sampled set.
    Each guessed p-subset is modeled as (p+2)*(n-k) binary operations for
    syndrome accumulation, inverse application/weight handling.  These are
    deliberately simple accounting units, useful for relative screening only.
    """
    probability = lee_brickell_success_probability(n, k, weight, p)
    if probability == 0.0:
        expected_sets = math.inf
        estimated_total = math.inf
    else:
        expected_sets = 1.0 / probability
        parity_size = n - k
        guesses = math.comb(k, p)
        elimination = parity_size**3
        guess_ops = guesses * (p + 2) * parity_size
        estimated_total = expected_sets * (elimination + guess_ops)
        return LeeBrickellCostPoint(
            n=n,
            k=k,
            weight=weight,
            p=p,
            success_probability_per_information_set=probability,
            expected_information_sets=expected_sets,
            guesses_per_invertible_set=guesses,
            elimination_ops_per_set=elimination,
            guess_ops_per_set=guess_ops,
            estimated_total_ops=estimated_total,
        )

    parity_size = n - k
    guesses = math.comb(k, p)
    return LeeBrickellCostPoint(
        n=n,
        k=k,
        weight=weight,
        p=p,
        success_probability_per_information_set=probability,
        expected_information_sets=expected_sets,
        guesses_per_invertible_set=guesses,
        elimination_ops_per_set=parity_size**3,
        guess_ops_per_set=guesses * (p + 2) * parity_size,
        estimated_total_ops=estimated_total,
    )


def best_lee_brickell_cost(
    n: int,
    k: int,
    weight: int,
    *,
    max_p: int = 4,
) -> LeeBrickellCostPoint:
    if max_p < 0:
        raise ValueError("max_p must be non-negative")
    upper = min(max_p, k, weight)
    points = [
        lee_brickell_cost_point(n, k, weight, p)
        for p in range(upper + 1)
        if weight - p <= n - k
    ]
    if not points:
        raise ValueError("no valid Lee-Brickell p values for this profile")
    return min(points, key=lambda point: point.estimated_total_ops)


def recover_sparse_error_lee_brickell(
    pk: CodePKEPublicKey,
    *,
    p: int,
    rng: BitRNG | None = None,
    max_information_sets: int = 10_000,
) -> LeeBrickellRecoveryResult:
    """Recover the advertised sparse error with generalized ISD.

    The routine is intended for reduced parameters.  It enumerates all p-error
    guesses inside each invertible information set, so large p is deliberately
    expensive and should be used only in research fixtures.
    """
    if max_information_sets <= 0:
        raise ValueError("max_information_sets must be positive")
    params = pk.params
    if not 0 <= p <= min(params.k, params.secret_weight):
        raise ValueError("p is outside the possible information-set error count")
    parity_size = params.n - params.k
    if params.secret_weight - p > parity_size:
        raise ValueError("remaining error weight does not fit parity positions")

    source = secrets.SystemRandom() if rng is None else rng
    parity_checks = nullspace_basis(pk.generator, params.n)
    if len(parity_checks) != parity_size:
        raise ValueError("public parity-check basis has unexpected dimension")
    target = _pack_syndrome(
        tuple(inner_product(row, pk.noisy_codeword) for row in parity_checks)
    )
    column_syndromes = tuple(
        _column_syndrome(parity_checks, position)
        for position in range(params.n)
    )

    invertible_sets = 0
    guesses_tested = 0
    all_positions = tuple(range(params.n))

    for sampled in range(1, max_information_sets + 1):
        parity_positions = tuple(sorted(source.sample(range(params.n), parity_size)))
        parity_lookup = set(parity_positions)
        information_positions = tuple(
            position for position in all_positions if position not in parity_lookup
        )

        restricted_rows = tuple(
            _restrict_row(row, parity_positions) for row in parity_checks
        )
        inverse = _invert_square_gf2(restricted_rows, parity_size)
        if inverse is None:
            continue
        invertible_sets += 1

        for guessed_positions in combinations(information_positions, p):
            guesses_tested += 1
            info_error = 0
            rhs = target
            for position in guessed_positions:
                info_error |= 1 << position
                rhs ^= column_syndromes[position]

            parity_local = _solve_with_inverse(inverse, rhs)
            if parity_local.bit_count() != params.secret_weight - p:
                continue
            candidate = info_error | _expand_positions(parity_local, parity_positions)
            if candidate.bit_count() != params.secret_weight:
                continue

            syndrome = _pack_syndrome(
                tuple(inner_product(row, candidate) for row in parity_checks)
            )
            if syndrome == target:
                return LeeBrickellRecoveryResult(
                    witness=candidate,
                    p=p,
                    information_sets_sampled=sampled,
                    invertible_information_sets=invertible_sets,
                    guesses_tested=guesses_tested,
                )

    raise ValueError("Lee-Brickell attack did not find a sparse witness within the limit")
