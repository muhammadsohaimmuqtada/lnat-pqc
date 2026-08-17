"""Hybrid-Prange quantum-memory/time trade-off from Esser et al.

This module ports Theorem 1 from Esser et al., "An Optimized Quantum
Implementation of ISD on Scalable Quantum Resources" (ePrint 2021/1608,
arXiv:2112.06157).

The theorem considers a classical co-processor that guesses ``alpha*n`` zero
coordinates of the hidden error and sends the shortened instance to the quantum
Prange circuit.  Writing ``R=k/n``, ``tau=w/n`` and using a qubit-reduction
factor ``delta`` in [0,1], the paper sets

    alpha = (1-delta) * R

and gives a *dimensionless asymptotic time exponent* ``t(delta)`` such that the
hybrid attack runs in time ``T_C ** t(delta)`` when the classical Prange attack
runs in time ``T_C``.  The matrix-representation memory is approximately
``delta * (1-R) * R * n^2`` qubits.

This is not a finite gate-count estimator.  The matrix-memory expression does
not include all ancillas/circuit overhead, and ``t(delta)`` is an asymptotic
complexity exponent.  The finite wrapper below uses an integer number of
classically guessed zero coordinates so reduced code dimensions are always
well-defined.
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


def binary_entropy(x: float) -> float:
    """Binary entropy H(x), in bits."""
    if not isinstance(x, (int, float)) or isinstance(x, bool):
        raise TypeError("x must be a real number")
    value = float(x)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("x must lie in [0, 1]")
    if value in (0.0, 1.0):
        return 0.0
    return -value * math.log2(value) - (1.0 - value) * math.log2(1.0 - value)


def hybrid_prange_time_exponent(rate: float, error_rate: float, delta: float) -> float:
    """Return Theorem-1 Hybrid-Prange time exponent ``t(delta)``.

    The theorem is instantiated for a nonzero error rate that fits within the
    Prange complement, i.e. ``0 < tau <= 1-R``.  ``delta=1`` recovers the full
    quantum Prange exponent 1/2; ``delta=0`` recovers the classical exponent 1.
    """
    for name, value in (("rate", rate), ("error_rate", error_rate), ("delta", delta)):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError(f"{name} must be a real number")
        if not math.isfinite(float(value)):
            raise ValueError(f"{name} must be finite")

    R = float(rate)
    tau = float(error_rate)
    d = float(delta)
    if not 0.0 < R < 1.0:
        raise ValueError("rate must lie in (0, 1)")
    if not 0.0 < tau <= 1.0 - R:
        raise ValueError("error_rate must lie in (0, 1-rate]")
    if not 0.0 <= d <= 1.0:
        raise ValueError("delta must lie in [0, 1]")

    alpha = (1.0 - d) * R
    denominator = binary_entropy(tau) - (1.0 - R) * binary_entropy(tau / (1.0 - R))
    if denominator <= 0.0:
        raise ValueError("degenerate classical Prange exponent")

    quantum_gain_term = (
        (1.0 - alpha) * binary_entropy(tau / (1.0 - alpha))
        - (1.0 - R) * binary_entropy(tau / (1.0 - R))
    )
    exponent = 1.0 - 0.5 * quantum_gain_term / denominator

    # Numerical noise at the endpoints must not move the theorem outside its
    # classical/full-quantum interval.
    if abs(exponent - 0.5) < 1e-15:
        return 0.5
    if abs(exponent - 1.0) < 1e-15:
        return 1.0
    return exponent


@dataclass(frozen=True)
class HybridPrangeTradeoff:
    n: int
    k: int
    weight: int
    guessed_zero_positions: int
    retained_quantum_dimension: int
    qubit_fraction_delta: float
    alpha: float
    reduced_n: int
    reduced_k: int
    reduced_weight: int
    matrix_representation_qubits: int
    full_matrix_representation_qubits: int
    time_exponent: float
    paper_eprint: str = PAPER_EPRINT
    paper_arxiv: str = PAPER_ARXIV
    reference_repository: str = QISD_REPOSITORY
    reference_commit: str = QISD_REFERENCE_COMMIT

    @property
    def matrix_memory_fraction(self) -> float:
        if self.full_matrix_representation_qubits == 0:
            return 0.0
        return self.matrix_representation_qubits / self.full_matrix_representation_qubits

    @property
    def matrix_memory_reduction_fraction(self) -> float:
        return 1.0 - self.matrix_memory_fraction


def assess_hybrid_prange_tradeoff(
    n: int,
    k: int,
    weight: int,
    guessed_zero_positions: int,
) -> HybridPrangeTradeoff:
    """Instantiate Theorem 1 using an integer zero-coordinate guess count.

    ``guessed_zero_positions`` is the finite analogue of ``alpha*n``.  The
    quantum subinstance has parameters ``(n-a, k-a, w)``.  The returned matrix
    qubit count is the theorem's matrix-representation term, not total circuit
    width.
    """
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (n, k, weight, guessed_zero_positions)):
        raise TypeError("n, k, weight, and guessed_zero_positions must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 < weight <= n - k:
        raise ValueError("weight must lie in [1, n-k]")
    if not 0 <= guessed_zero_positions <= k:
        raise ValueError("guessed_zero_positions must lie in [0, k]")

    a = guessed_zero_positions
    retained_k = k - a
    delta = retained_k / k
    alpha = a / n
    R = k / n
    tau = weight / n

    exponent = hybrid_prange_time_exponent(R, tau, delta)
    full_matrix_qubits = (n - k) * k
    matrix_qubits = (n - k) * retained_k

    return HybridPrangeTradeoff(
        n=n,
        k=k,
        weight=weight,
        guessed_zero_positions=a,
        retained_quantum_dimension=retained_k,
        qubit_fraction_delta=delta,
        alpha=alpha,
        reduced_n=n - a,
        reduced_k=retained_k,
        reduced_weight=weight,
        matrix_representation_qubits=matrix_qubits,
        full_matrix_representation_qubits=full_matrix_qubits,
        time_exponent=exponent,
    )
