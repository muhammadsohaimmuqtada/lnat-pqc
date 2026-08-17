"""Unified classical/quantum/correctness gate for code-based LNAT research.

`code_modern_frontier` is intentionally a *classical* syndrome-decoding screen.
`code_quantum_isd` is intentionally a minimal quantum-search rejection
baseline. This module composes them so a caller cannot obtain a positive
"post-quantum frontier" result from the classical estimator alone.

Passing this gate is still only a research milestone. The quantum component is
Groverized Prange/support enumeration rather than a finite best-known quantum
ISD resource estimate, so a passing result must not be presented as a security
level or deployment recommendation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from code_modern_frontier import Estimator, ModernAttackAssessment, assess_modern_candidate
from code_quantum_isd import QuantumISDScreen, assess_quantum_isd
from code_sd_estimator import estimate_upstream_isd


@dataclass(frozen=True)
class PostQuantumFrontierAssessment:
    """Combined research assessment for one random-code parameter point."""

    classical: ModernAttackAssessment
    quantum: QuantumISDScreen

    def __post_init__(self) -> None:
        classical_point = (self.classical.n, self.classical.k, self.classical.weight)
        quantum_point = (self.quantum.n, self.quantum.k, self.quantum.weight)
        if classical_point != quantum_point:
            raise ValueError("classical and quantum assessments target different points")

    @property
    def n(self) -> int:
        return self.classical.n

    @property
    def k(self) -> int:
        return self.classical.k

    @property
    def weight(self) -> int:
        return self.classical.weight

    def passes(
        self,
        *,
        classical_attack_floor_bits: float,
        quantum_iteration_floor_bits: float,
        kem_failure_ceiling: float,
    ) -> bool:
        """Require classical, quantum-baseline, and correctness gates together."""
        _validate_floor("classical_attack_floor_bits", classical_attack_floor_bits)
        _validate_floor("quantum_iteration_floor_bits", quantum_iteration_floor_bits)
        if not 0.0 < kem_failure_ceiling < 1.0:
            raise ValueError("kem_failure_ceiling must be in (0, 1)")
        return (
            self.classical.passes(classical_attack_floor_bits, kem_failure_ceiling)
            and self.quantum.passes_iteration_floor(quantum_iteration_floor_bits)
        )


def _validate_floor(name: str, value: float) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{name} must be a real number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{name} must be finite and non-negative")


def assess_post_quantum_candidate(
    n: int,
    k: int,
    weight: int,
    *,
    encryption_error_weight: int = 1,
    encapsulated_bits: int = 128,
    kem_failure_ceiling: float = 1e-9,
    max_repetitions: int = 4096,
    classical_estimator: Estimator = estimate_upstream_isd,
) -> PostQuantumFrontierAssessment:
    """Assess one point under both classical and quantum-baseline attack models."""
    classical = assess_modern_candidate(
        n,
        k,
        weight,
        encryption_error_weight=encryption_error_weight,
        encapsulated_bits=encapsulated_bits,
        kem_failure_ceiling=kem_failure_ceiling,
        max_repetitions=max_repetitions,
        estimator=classical_estimator,
    )
    quantum = assess_quantum_isd(n, k, weight)
    return PostQuantumFrontierAssessment(classical=classical, quantum=quantum)


def screen_post_quantum_candidate(
    n: int,
    k: int,
    weight: int,
    *,
    classical_attack_floor_bits: float,
    quantum_iteration_floor_bits: float,
    encryption_error_weight: int = 1,
    encapsulated_bits: int = 128,
    kem_failure_ceiling: float = 1e-9,
    max_repetitions: int = 4096,
    classical_estimator: Estimator = estimate_upstream_isd,
) -> PostQuantumFrontierAssessment | None:
    """Return a point only if all currently implemented research gates pass."""
    _validate_floor("classical_attack_floor_bits", classical_attack_floor_bits)
    _validate_floor("quantum_iteration_floor_bits", quantum_iteration_floor_bits)
    assessment = assess_post_quantum_candidate(
        n,
        k,
        weight,
        encryption_error_weight=encryption_error_weight,
        encapsulated_bits=encapsulated_bits,
        kem_failure_ceiling=kem_failure_ceiling,
        max_repetitions=max_repetitions,
        classical_estimator=classical_estimator,
    )
    return assessment if assessment.passes(
        classical_attack_floor_bits=classical_attack_floor_bits,
        quantum_iteration_floor_bits=quantum_iteration_floor_bits,
        kem_failure_ceiling=kem_failure_ceiling,
    ) else None
