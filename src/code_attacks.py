"""Attacks against the toy random-code/LNAT-code bridge experiments.

These routines intentionally exploit the tiny sparse-witness spaces used by
research profiles.  They are not generic claims about practical code-based
cryptography; they exist to keep the repository honest about its toy security
boundary.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from itertools import combinations

from code_pke_reference import CodePKEPublicKey, inner_product, nullspace_basis


@dataclass(frozen=True)
class SparseWitnessRecoveryResult:
    witness: int
    candidates_tested: int
    total_candidates: int

    @property
    def search_fraction(self) -> float:
        return self.candidates_tested / self.total_candidates


def _vector_from_positions(positions: tuple[int, ...]) -> int:
    value = 0
    for position in positions:
        value |= 1 << position
    return value


def recover_sparse_error_from_public_key(
    pk: CodePKEPublicKey,
    *,
    max_candidates: int | None = None,
) -> SparseWitnessRecoveryResult:
    """Recover an exact-weight error by public syndrome enumeration.

    For public ``y = c + e`` with ``c`` in code ``C``, every parity-check
    vector ``h`` in ``C^perp`` satisfies ``<h,e> = <h,y>``.  Enumerating the
    advertised weight-w vectors and matching this public syndrome therefore
    recovers a decoding witness whenever the toy instance has a unique such
    vector.
    """
    params = pk.params
    total = math.comb(params.n, params.secret_weight)
    if max_candidates is not None and max_candidates <= 0:
        raise ValueError("max_candidates must be positive")

    parity_checks = nullspace_basis(pk.generator, params.n)
    target = tuple(inner_product(check, pk.noisy_codeword) for check in parity_checks)
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
