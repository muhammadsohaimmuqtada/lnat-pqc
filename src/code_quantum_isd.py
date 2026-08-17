"""Transparent quantum-search screening for random-code LNAT research profiles.

The maintained syndrome-decoding estimator currently wired into this repository
is a classical estimator. A post-quantum research profile must therefore be
screened separately against quantum decoding attacks.

This module deliberately implements only a minimal, easy-to-audit finite
rejection baseline: Grover/amplitude-amplification applied to Prange
information-set search and to direct sparse-support enumeration. If a
classical search has search-space exponent ``b``, the idealized Grover
iteration exponent is ``b / 2``.

The reported values are *quantum search iteration exponents*, not quantum gate
counts and not security levels. Reversible linear algebra, memory, circuit
width/depth, constants, and more advanced quantum ISD algorithms are outside
this tiny model. In particular, passing this screen is necessary but nowhere
near sufficient for a post-quantum security claim, while failing it is enough
to reject a candidate under this public attack path.

References motivating the baseline include Bernstein's "Grover vs. McEliece"
(PQCrypto 2010) and Kachigar--Tillich's "Quantum Information Set Decoding
Algorithms" (PQCrypto 2017, arXiv:1703.00263). The latter also gives quantum
walk improvements over Groverized Prange, so this module must not be treated as
a best-known-quantum-attack estimator.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_attacks import prange_expected_trial_bits
from code_profile_audit import sparse_witness_enumeration_bits


@dataclass(frozen=True)
class QuantumISDScreen:
    """Finite query/iteration-model screening result for one ``(n,k,w)`` point."""

    n: int
    k: int
    weight: int
    classical_prange_trial_bits: float
    grover_prange_iteration_bits: float
    classical_support_enumeration_bits: float
    grover_support_iteration_bits: float
    effective_quantum_search_bits: float
    effective_quantum_search_attack: str

    def passes_iteration_floor(self, bits: float) -> bool:
        """Return whether the modeled quantum search exponent reaches ``bits``."""
        if not isinstance(bits, (int, float)) or isinstance(bits, bool):
            raise TypeError("bits must be a real number")
        if not math.isfinite(float(bits)) or bits < 0:
            raise ValueError("bits must be finite and non-negative")
        return self.effective_quantum_search_bits >= float(bits)


def groverized_iteration_bits(classical_search_bits: float) -> float:
    """Idealized Grover iteration exponent for a classical search exponent.

    ``classical_search_bits`` is ``log2(N)`` for the relevant expected search
    count/space. Grover search uses ``Theta(sqrt(N))`` oracle iterations, hence
    the exponent halves. Polynomial/reversible-oracle cost is intentionally not
    folded into this number because doing so would require a concrete quantum
    circuit model.
    """
    if not isinstance(classical_search_bits, (int, float)) or isinstance(
        classical_search_bits, bool
    ):
        raise TypeError("classical_search_bits must be a real number")
    value = float(classical_search_bits)
    if math.isnan(value) or value < 0:
        raise ValueError("classical_search_bits must be non-negative")
    if math.isinf(value):
        return math.inf
    return value / 2.0


def assess_quantum_isd(n: int, k: int, weight: int) -> QuantumISDScreen:
    """Assess transparent Groverized search baselines for one binary SD point."""
    if not isinstance(n, int) or not isinstance(k, int) or not isinstance(weight, int):
        raise TypeError("n, k, and weight must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")

    prange_bits = prange_expected_trial_bits(n, k, weight)
    support_bits = sparse_witness_enumeration_bits(n, weight)
    grover_prange = groverized_iteration_bits(prange_bits)
    grover_support = groverized_iteration_bits(support_bits)

    if grover_prange <= grover_support:
        effective_bits = grover_prange
        effective_attack = "GroverizedPrange"
    else:
        effective_bits = grover_support
        effective_attack = "GroverizedSupportEnumeration"

    return QuantumISDScreen(
        n=n,
        k=k,
        weight=weight,
        classical_prange_trial_bits=prange_bits,
        grover_prange_iteration_bits=grover_prange,
        classical_support_enumeration_bits=support_bits,
        grover_support_iteration_bits=grover_support,
        effective_quantum_search_bits=effective_bits,
        effective_quantum_search_attack=effective_attack,
    )
