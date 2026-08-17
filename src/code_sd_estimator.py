"""Pinned upstream syndrome-decoding estimator bridge.

This module cross-checks LNAT random-code research parameters against the
Crypto-TII ``cryptographic_estimators`` package. It deliberately does not copy
or reimplement BJMM/May-Ozerov formulas. The upstream project already provides
finite-parameter estimators for Prange, Stern, Dumer, BJMM, Both-May,
May-Ozerov, and related algorithms.

The output is an attack estimate, not a security proof. A reported time value
is meaningful only under the upstream estimator's cost model and options.
"""

from __future__ import annotations

import importlib.metadata
import math
from dataclasses import dataclass
from numbers import Real
from typing import Any

EXPECTED_UPSTREAM_VERSION = "2.1.1"
PACKAGE_NAME = "cryptographic-estimators"


@dataclass(frozen=True)
class UpstreamISDPoint:
    algorithm: str
    time_bits: float
    memory_bits: float | None
    parameters: dict[str, Any]


@dataclass(frozen=True)
class UpstreamISDReport:
    n: int
    k: int
    weight: int
    package_version: str
    points: tuple[UpstreamISDPoint, ...]

    @property
    def fastest(self) -> UpstreamISDPoint:
        if not self.points:
            raise ValueError("report contains no finite attack estimates")
        return min(self.points, key=lambda point: point.time_bits)

    def by_algorithm(self, name: str) -> UpstreamISDPoint:
        for point in self.points:
            if point.algorithm == name:
                return point
        raise KeyError(name)


def upstream_available() -> bool:
    try:
        importlib.metadata.version(PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError:
        return False
    return True


def _require_instance(n: int, k: int, weight: int) -> None:
    if not isinstance(n, int) or not isinstance(k, int) or not isinstance(weight, int):
        raise TypeError("n, k, and weight must be integers")
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, Real):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def estimate_upstream_isd(
    n: int,
    k: int,
    weight: int,
    *,
    require_pinned_version: bool = True,
    memory_bound: float = math.inf,
) -> UpstreamISDReport:
    """Run Crypto-TII's binary syndrome-decoding estimator."""
    _require_instance(n, k, weight)
    try:
        package_version = importlib.metadata.version(PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "cryptographic-estimators is not installed; install the 'estimator' extra"
        ) from exc

    if require_pinned_version and package_version != EXPECTED_UPSTREAM_VERSION:
        raise RuntimeError(
            f"expected {PACKAGE_NAME}=={EXPECTED_UPSTREAM_VERSION}, got {package_version}"
        )

    from cryptographic_estimators.SDEstimator import SDEstimator

    estimator = SDEstimator(
        n=n,
        k=k,
        w=weight,
        bit_complexities=1,
        memory_bound=memory_bound,
    )
    raw = estimator.estimate()
    points: list[UpstreamISDPoint] = []
    for algorithm, payload in raw.items():
        estimate = payload.get("estimate", {})
        time_bits = _finite_number(estimate.get("time"))
        if time_bits is None:
            continue
        memory_bits = _finite_number(estimate.get("memory"))
        parameters = estimate.get("parameters", {})
        if not isinstance(parameters, dict):
            parameters = {"raw": parameters}
        points.append(
            UpstreamISDPoint(
                algorithm=algorithm,
                time_bits=time_bits,
                memory_bits=memory_bits,
                parameters=dict(parameters),
            )
        )

    if not points:
        raise RuntimeError("upstream estimator returned no finite attack estimates")
    points.sort(key=lambda point: (point.time_bits, point.algorithm))
    return UpstreamISDReport(
        n=n,
        k=k,
        weight=weight,
        package_version=package_version,
        points=tuple(points),
    )
