"""Paper-grounded resource surface for the quantum Prange attack.

This module instantiates the *explicit* width formulas and the asymptotic depth
scale from Esser et al., "An Optimized Quantum Implementation of ISD on
Scalable Quantum Resources" (ePrint 2021/1608, arXiv:2112.06157).

The paper's supplementary implementation is qiboteam/qISD.  We pin the source
revision used as provenance, but intentionally do not vendor or execute Qibo in
this package: the authors' simulator is designed for small circuits, while our
research points require hundreds of thousands of logical qubits.

Important units:

- ``*_qubits`` are exact logical-qubit counts from Table 2's closed-form width
  formulas for the stated Prange circuit layouts.
- ``grover_iteration_bits`` is log2 of the idealized amplitude-amplification
  iteration count derived from Prange's success probability.
- ``width_optimized_depth_scale_bits`` is log2 of the Table-2 asymptotic scale
  ``n^3 log2(n) / sqrt(q)``.  Because the paper states this with big-O notation,
  this is NOT an exact circuit depth or a gate count and contains unknown
  multiplicative constants.

None of these values is a cryptographic security level.  They provide concrete
resource accounting for the currently implemented Groverized-Prange attack;
stronger quantum ISD remains a separate attack-analysis requirement.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_attacks import prange_expected_trial_bits

PAPER_TITLE = "An Optimized Quantum Implementation of ISD on Scalable Quantum Resources"
PAPER_EPRINT = "2021/1608"
PAPER_ARXIV = "2112.06157"
QISD_REPOSITORY = "qiboteam/qISD"
QISD_REFERENCE_COMMIT = "456b3c60987e426a18d4ed4e5ebeaee3d2570958"


@dataclass(frozen=True)
class QuantumPrangeResourceEstimate:
    n: int
    k: int
    weight: int
    prange_success_log2: float
    classical_expected_trial_bits: float
    grover_iteration_bits: float
    width_optimized_qubits: int
    depth_optimized_qubits: int
    width_optimized_depth_scale_bits: float
    paper_eprint: str = PAPER_EPRINT
    paper_arxiv: str = PAPER_ARXIV
    reference_repository: str = QISD_REPOSITORY
    reference_commit: str = QISD_REFERENCE_COMMIT

    @property
    def width_optimized_mebiqubits(self) -> float:
        """Width-optimized logical qubits in units of 2^20 qubits."""
        return self.width_optimized_qubits / (1 << 20)

    @property
    def depth_optimized_mebiqubits(self) -> float:
        """Depth-oriented logical qubits in units of 2^20 qubits."""
        return self.depth_optimized_qubits / (1 << 20)


def _validate_point(n: int, k: int, weight: int) -> None:
    if not isinstance(n, int) or not isinstance(k, int) or not isinstance(weight, int):
        raise TypeError("n, k, and weight must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n - k:
        raise ValueError("Prange baseline requires weight in [0, n-k]")


def idealized_grover_iteration_bits(classical_trial_bits: float) -> float:
    """Return log2 of the continuous idealized Grover iteration estimate.

    For success probability ``q = 2^-b`` and tiny q, amplitude amplification
    needs approximately ``pi/(4*sqrt(q))`` oracle iterations.  The returned
    value therefore includes the ``pi/4`` constant, unlike the simpler ``b/2``
    rejection exponent used by :mod:`code_quantum_isd`.

    This remains an idealized iteration count, not a circuit-depth estimate.
    """
    if not isinstance(classical_trial_bits, (int, float)) or isinstance(
        classical_trial_bits, bool
    ):
        raise TypeError("classical_trial_bits must be a real number")
    value = float(classical_trial_bits)
    if math.isnan(value) or value < 0:
        raise ValueError("classical_trial_bits must be non-negative")
    if math.isinf(value):
        return math.inf
    return 0.5 * value + math.log2(math.pi / 4.0)


def width_optimized_qubits(n: int, k: int) -> int:
    """Exact Table-2 logical-qubit formula for the width-optimized circuit."""
    if not isinstance(n, int) or not isinstance(k, int):
        raise TypeError("n and k must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    return (n - k + 2) * (k + 3) - 7


def depth_optimized_qubits(n: int, k: int) -> int:
    """Exact Table-2 logical-qubit formula for the depth-oriented full circuit."""
    if not isinstance(n, int) or not isinstance(k, int):
        raise TypeError("n and k must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    return (n - k + 1) * (n + 2) - 3


def width_optimized_depth_scale_bits(n: int, classical_trial_bits: float) -> float:
    """Log2 of Table 2's ``n^3 log(n)/sqrt(q)`` asymptotic depth scale.

    The ``sqrt(q)`` factor uses the Prange success probability.  This function
    uses log base 2 consistently; changing the logarithm base only changes an
    asymptotic constant, which is already hidden by the paper's big-O notation.
    """
    if not isinstance(n, int):
        raise TypeError("n must be an integer")
    if n <= 1:
        raise ValueError("n must be greater than 1")
    grover_bits = idealized_grover_iteration_bits(classical_trial_bits)
    return grover_bits + 3.0 * math.log2(n) + math.log2(math.log2(n))


def assess_quantum_prange_resources(
    n: int,
    k: int,
    weight: int,
) -> QuantumPrangeResourceEstimate:
    """Instantiate the paper's Prange resource surface for one SD point."""
    _validate_point(n, k, weight)
    trial_bits = prange_expected_trial_bits(n, k, weight)
    return QuantumPrangeResourceEstimate(
        n=n,
        k=k,
        weight=weight,
        prange_success_log2=-trial_bits,
        classical_expected_trial_bits=trial_bits,
        grover_iteration_bits=idealized_grover_iteration_bits(trial_bits),
        width_optimized_qubits=width_optimized_qubits(n, k),
        depth_optimized_qubits=depth_optimized_qubits(n, k),
        width_optimized_depth_scale_bits=width_optimized_depth_scale_bits(n, trial_bits),
    )
