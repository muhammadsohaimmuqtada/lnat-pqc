"""Finite proof-component accounting for Punctured/Combined-Hybrid ISD.

This module ports the explicit combinatorial factors from Theorem 2
(Punctured-Hybrid) and Theorem 3 (Combined-Hybrid) of Esser et al.,
"An Optimized Quantum Implementation of ISD on Scalable Quantum Resources"
(ePrint 2021/1608, arXiv:2112.06157), cross-checked against the authors'
``qiboteam/qISD`` supplementary ``hybrid.sage`` implementation.

The central output, ``proof_time_proxy_bits``, is log2 of the theorem proof's
explicit combinatorial factors, with the paper's soft-O polynomial factors and
hidden circuit constants omitted.  It is therefore NOT a finite gate count,
wall-clock estimate, or cryptographic security level.

All finite parameters are integers:

- ``a`` = classically guessed zero coordinates (Combined-Hybrid only),
- ``b`` = omitted parity-check equations / punctured coordinates,
- ``p`` = target error weight on the omitted part.

The reduced quantum instance has

    N  = n - a - b
    k' = k - a
    r' = n - k - b
    u  = w - p

with matrix-representation term ``k' * r'``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_quantum_prange_resources import (
    PAPER_ARXIV,
    PAPER_EPRINT,
    QISD_REFERENCE_COMMIT,
    QISD_REPOSITORY,
)

_LOG2 = math.log(2.0)


def log2_binomial(n: int, k: int) -> float:
    """Stable ``log2(binomial(n,k))`` for integer parameters."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise TypeError("n must be an integer")
    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError("k must be an integer")
    if n < 0:
        raise ValueError("n must be non-negative")
    if not 0 <= k <= n:
        raise ValueError("require 0 <= k <= n")
    if k == 0 or k == n:
        return 0.0
    k = min(k, n - k)
    return (
        math.lgamma(n + 1.0)
        - math.lgamma(k + 1.0)
        - math.lgamma(n - k + 1.0)
    ) / _LOG2


@dataclass(frozen=True)
class HybridProofCost:
    """Explicit proof-component accounting for one finite hybrid parameter set."""

    n: int
    k: int
    weight: int
    guessed_zero_positions: int
    omitted_parity_equations: int
    punctured_weight: int
    reduced_length: int
    reduced_dimension: int
    reduced_parity_checks: int
    reduced_weight: int
    matrix_representation_qubits: int
    full_matrix_representation_qubits: int
    matrix_memory_fraction: float
    log2_correct_zero_guess_probability: float
    log2_expected_outer_iterations: float
    log2_expected_reduced_solutions: float
    log2_repeat_factor: float
    log2_quantum_subroutine_proxy: float
    proof_time_proxy_bits: float
    paper_eprint: str = PAPER_EPRINT
    paper_arxiv: str = PAPER_ARXIV
    reference_repository: str = QISD_REPOSITORY
    reference_commit: str = QISD_REFERENCE_COMMIT

    @property
    def is_punctured_hybrid(self) -> bool:
        return self.guessed_zero_positions == 0


def _validate_parameters(
    n: int,
    k: int,
    weight: int,
    guessed_zero_positions: int,
    omitted_parity_equations: int,
    punctured_weight: int,
) -> None:
    values = (
        n,
        k,
        weight,
        guessed_zero_positions,
        omitted_parity_equations,
        punctured_weight,
    )
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        raise TypeError("all finite hybrid parameters must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    redundancy = n - k
    if not 0 < weight <= redundancy:
        raise ValueError("weight must lie in [1, n-k]")
    if not 0 <= guessed_zero_positions < k:
        raise ValueError("guessed_zero_positions must lie in [0, k)")
    if guessed_zero_positions > n - weight:
        raise ValueError("cannot correctly guess more zero coordinates than exist")
    if not 0 <= omitted_parity_equations < redundancy:
        raise ValueError("omitted_parity_equations must lie in [0, n-k)")
    if not 0 <= punctured_weight <= min(weight, omitted_parity_equations):
        raise ValueError("punctured_weight must lie in [0, min(weight, omitted)]")

    reduced_weight = weight - punctured_weight
    reduced_parity = redundancy - omitted_parity_equations
    if reduced_weight > reduced_parity:
        raise ValueError(
            "reduced weight must not exceed retained parity-check dimension"
        )


def assess_combined_hybrid(
    n: int,
    k: int,
    weight: int,
    guessed_zero_positions: int,
    omitted_parity_equations: int,
    punctured_weight: int,
) -> HybridProofCost:
    """Evaluate the explicit Theorem-3 proof factors for one integer point.

    For ``guessed_zero_positions == 0`` this reduces to the Theorem-2
    Punctured-Hybrid proof accounting.
    """
    _validate_parameters(
        n,
        k,
        weight,
        guessed_zero_positions,
        omitted_parity_equations,
        punctured_weight,
    )

    a = guessed_zero_positions
    b = omitted_parity_equations
    p = punctured_weight
    redundancy = n - k
    reduced_length = n - a - b
    reduced_dimension = k - a
    reduced_parity = redundancy - b
    reduced_weight = weight - p

    # Correct zero-coordinate guess in Theorem 3.  For a=0 this is exactly 1.
    log_q_zero = log2_binomial(n - a, weight) - log2_binomial(n, weight)

    # Expected outer Punctured-Hybrid permutations E (Theorem 3 proof).
    log_outer = (
        log2_binomial(n - a, weight)
        - log2_binomial(reduced_length, reduced_weight)
        - log2_binomial(b, p)
    )

    # Expected number of reduced-instance solutions.  The quantum routine and
    # the outer repetition use max(1,S), per Theorem 2 / Theorem 3 proof.
    log_solutions = log2_binomial(reduced_length, reduced_weight) - reduced_parity
    log_repeat = max(0.0, log_solutions)

    # T_Q = O~(sqrt(C(N,u) / (max(1,S) * C(r',u)))).
    log_quantum = 0.5 * (
        log2_binomial(reduced_length, reduced_weight)
        - log_repeat
        - log2_binomial(reduced_parity, reduced_weight)
    )

    # T_CH = q_zero^-1 * E * T_Q * max(1,S).
    # Punctured-Hybrid is the a=0 specialization.
    total = -log_q_zero + log_outer + log_quantum + log_repeat

    full_matrix_qubits = k * redundancy
    matrix_qubits = reduced_dimension * reduced_parity

    return HybridProofCost(
        n=n,
        k=k,
        weight=weight,
        guessed_zero_positions=a,
        omitted_parity_equations=b,
        punctured_weight=p,
        reduced_length=reduced_length,
        reduced_dimension=reduced_dimension,
        reduced_parity_checks=reduced_parity,
        reduced_weight=reduced_weight,
        matrix_representation_qubits=matrix_qubits,
        full_matrix_representation_qubits=full_matrix_qubits,
        matrix_memory_fraction=matrix_qubits / full_matrix_qubits,
        log2_correct_zero_guess_probability=log_q_zero,
        log2_expected_outer_iterations=log_outer,
        log2_expected_reduced_solutions=log_solutions,
        log2_repeat_factor=log_repeat,
        log2_quantum_subroutine_proxy=log_quantum,
        proof_time_proxy_bits=total,
    )


def assess_punctured_hybrid(
    n: int,
    k: int,
    weight: int,
    omitted_parity_equations: int,
    punctured_weight: int,
) -> HybridProofCost:
    """Evaluate Theorem-2 Punctured-Hybrid proof factors for one integer point."""
    return assess_combined_hybrid(
        n,
        k,
        weight,
        guessed_zero_positions=0,
        omitted_parity_equations=omitted_parity_equations,
        punctured_weight=punctured_weight,
    )


def optimize_punctured_weight(
    n: int,
    k: int,
    weight: int,
    guessed_zero_positions: int,
    omitted_parity_equations: int,
) -> HybridProofCost:
    """Choose the finite ``p`` minimizing the proof-component time proxy.

    Only ``p`` is optimized.  The zero-guess count ``a`` and omitted-equation
    count ``b`` remain caller-supplied policy/resource choices.
    """
    if not all(
        isinstance(v, int) and not isinstance(v, bool)
        for v in (n, k, weight, guessed_zero_positions, omitted_parity_equations)
    ):
        raise TypeError("all finite hybrid parameters must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    redundancy = n - k
    if not 0 < weight <= redundancy:
        raise ValueError("weight must lie in [1, n-k]")
    if not 0 <= guessed_zero_positions < k:
        raise ValueError("guessed_zero_positions must lie in [0, k)")
    if guessed_zero_positions > n - weight:
        raise ValueError("cannot correctly guess more zero coordinates than exist")
    if not 0 <= omitted_parity_equations < redundancy:
        raise ValueError("omitted_parity_equations must lie in [0, n-k)")

    reduced_parity = redundancy - omitted_parity_equations
    p_min = max(0, weight - reduced_parity)
    p_max = min(weight, omitted_parity_equations)
    if p_min > p_max:
        raise ValueError("no feasible punctured_weight for this finite parameter set")

    best: HybridProofCost | None = None
    for p in range(p_min, p_max + 1):
        candidate = assess_combined_hybrid(
            n,
            k,
            weight,
            guessed_zero_positions,
            omitted_parity_equations,
            p,
        )
        if best is None or candidate.proof_time_proxy_bits < best.proof_time_proxy_bits:
            best = candidate
    assert best is not None
    return best
