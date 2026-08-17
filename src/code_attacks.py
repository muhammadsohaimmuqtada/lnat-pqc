"""Attacks against the toy random-code/LNAT-code bridge experiments.

These routines intentionally target the public decoding instances exposed by
research profiles.  They are not generic claims about production code-based
cryptography; they exist to keep the repository honest about concrete public
attack paths.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from itertools import combinations

from code_pke_reference import BitRNG, CodePKEPublicKey, inner_product, nullspace_basis


@dataclass(frozen=True)
class SparseWitnessRecoveryResult:
    witness: int
    candidates_tested: int
    total_candidates: int

    @property
    def search_fraction(self) -> float:
        return self.candidates_tested / self.total_candidates


@dataclass(frozen=True)
class PrangeRecoveryResult:
    witness: int
    subsets_sampled: int
    invertible_subsets: int


def _vector_from_positions(positions: tuple[int, ...]) -> int:
    value = 0
    for position in positions:
        value |= 1 << position
    return value


def _public_syndrome(pk: CodePKEPublicKey) -> tuple[tuple[int, ...], tuple[int, ...]]:
    checks = nullspace_basis(pk.generator, pk.params.n)
    syndrome = tuple(inner_product(check, pk.noisy_codeword) for check in checks)
    return checks, syndrome


def recover_sparse_error_from_public_key(
    pk: CodePKEPublicKey,
    *,
    max_candidates: int | None = None,
) -> SparseWitnessRecoveryResult:
    """Recover an exact-weight error by public syndrome enumeration."""
    params = pk.params
    total = math.comb(params.n, params.secret_weight)
    if max_candidates is not None and max_candidates <= 0:
        raise ValueError("max_candidates must be positive")

    parity_checks, target = _public_syndrome(pk)
    tested = 0

    for positions in combinations(range(params.n), params.secret_weight):
        if max_candidates is not None and tested >= max_candidates:
            break
        tested += 1
        candidate = _vector_from_positions(positions)
        syndrome = tuple(inner_product(check, candidate) for check in parity_checks)
        if syndrome == target:
            return SparseWitnessRecoveryResult(candidate, tested, total)

    raise ValueError("no matching sparse witness found within search limit")


def _solve_square_gf2(rows: list[int], rhs: tuple[int, ...], variables: int) -> int | None:
    """Solve an invertible binary square system, returning packed solution bits."""
    if len(rows) != variables or len(rhs) != variables:
        raise ValueError("square system dimensions do not match")
    augmented = [row | ((bit & 1) << variables) for row, bit in zip(rows, rhs)]

    pivot_row = 0
    pivot_columns: list[int] = []
    for column in range(variables):
        selected = next(
            (index for index in range(pivot_row, variables) if (augmented[index] >> column) & 1),
            None,
        )
        if selected is None:
            continue
        augmented[pivot_row], augmented[selected] = augmented[selected], augmented[pivot_row]
        pivot = augmented[pivot_row]
        for index in range(variables):
            if index != pivot_row and ((augmented[index] >> column) & 1):
                augmented[index] ^= pivot
        pivot_columns.append(column)
        pivot_row += 1

    if pivot_row != variables:
        return None

    solution = 0
    for row, column in zip(augmented, pivot_columns):
        if (row >> variables) & 1:
            solution |= 1 << column
    return solution


def _restrict_check_to_positions(check: int, positions: tuple[int, ...]) -> int:
    compressed = 0
    for local, absolute in enumerate(positions):
        if (check >> absolute) & 1:
            compressed |= 1 << local
    return compressed


def prange_expected_information_sets(n: int, k: int, weight: int) -> float:
    """Combinatorial expected information-set trials for Prange decoding.

    This counts only the probability that a size-k information set is free of
    the weight-w error.  It is an iteration model, not a complete operation
    count and not a security estimate.
    """
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    parity_size = n - k
    if weight > parity_size:
        return math.inf
    return math.comb(n, weight) / math.comb(parity_size, weight)


def prange_expected_trial_bits(n: int, k: int, weight: int) -> float:
    expected = prange_expected_information_sets(n, k, weight)
    return math.inf if math.isinf(expected) else math.log2(expected)


def recover_sparse_error_prange(
    pk: CodePKEPublicKey,
    *,
    rng: BitRNG | None = None,
    max_subsets: int = 10_000,
) -> PrangeRecoveryResult:
    """Recover a sparse public decoding witness with a Prange-style attack.

    A parity-check matrix H for the public code satisfies H e^T = H y^T.
    Repeatedly choose n-k coordinates, solve the restricted square system, and
    accept a solution of the advertised weight whose public syndrome matches.
    """
    if max_subsets <= 0:
        raise ValueError("max_subsets must be positive")
    source = secrets.SystemRandom() if rng is None else rng
    params = pk.params
    parity_checks, target = _public_syndrome(pk)
    parity_size = params.n - params.k
    if len(parity_checks) != parity_size:
        raise ValueError("public parity-check basis has unexpected dimension")

    invertible = 0
    for sampled in range(1, max_subsets + 1):
        positions = tuple(sorted(source.sample(range(params.n), parity_size)))
        square_rows = [
            _restrict_check_to_positions(check, positions) for check in parity_checks
        ]
        local_solution = _solve_square_gf2(square_rows, target, parity_size)
        if local_solution is None:
            continue
        invertible += 1

        witness = 0
        for local, absolute in enumerate(positions):
            if (local_solution >> local) & 1:
                witness |= 1 << absolute
        if witness.bit_count() != params.secret_weight:
            continue
        syndrome = tuple(inner_product(check, witness) for check in parity_checks)
        if syndrome == target:
            return PrangeRecoveryResult(witness, sampled, invertible)

    raise ValueError("Prange attack did not find a sparse witness within the subset limit")
