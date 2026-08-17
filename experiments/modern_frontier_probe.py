#!/usr/bin/env python3
"""Validate the measured modern-ISD research frontier around the 128-bit screen."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import (
    ACTIVE_RESEARCH_POINT,
    BELOW_FLOOR_NEIGHBOR,
    ModernISDPolicy,
    evaluate_modern_isd_candidate,
)
from code_sd_estimator import estimate_upstream_isd


def _measure(point: tuple[int, int, int], policy: ModernISDPolicy):
    n, k, w = point
    report = estimate_upstream_isd(n, k, w)
    candidate = evaluate_modern_isd_candidate(
        n,
        k,
        w,
        policy,
        estimate_fn=lambda _n, _k, _w: report,
    )
    support_bits = __import__("code_profile_audit").sparse_witness_enumeration_bits(n, w)
    fastest = report.fastest
    effective_bits = min(fastest.time_bits, support_bits)
    effective_attack = fastest.algorithm if fastest.time_bits <= support_bits else "SupportEnumeration"
    return report, candidate, support_bits, effective_bits, effective_attack


def main() -> int:
    policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)

    lower_report, lower_candidate, lower_support, lower_effective, lower_attack = _measure(
        BELOW_FLOOR_NEIGHBOR, policy
    )
    active_report, active_candidate, active_support, active_effective, active_attack = _measure(
        ACTIVE_RESEARCH_POINT, policy
    )

    print(
        f"below-point={BELOW_FLOOR_NEIGHBOR} fastest={lower_report.fastest.algorithm} "
        f"upstream-bits={lower_report.fastest.time_bits:.6f} "
        f"support-bits={lower_support:.6f} effective={lower_effective:.6f} "
        f"effective-attack={lower_attack} accepted={lower_candidate is not None}"
    )
    print(
        f"active-point={ACTIVE_RESEARCH_POINT} fastest={active_report.fastest.algorithm} "
        f"upstream-bits={active_report.fastest.time_bits:.6f} "
        f"support-bits={active_support:.6f} effective={active_effective:.6f} "
        f"effective-attack={active_attack} accepted={active_candidate is not None}"
    )
    if active_candidate is not None:
        print(f"repetitions={active_candidate.repetitions}")
        print(f"cutoff={active_candidate.cutoff_ones}")
        print(f"kem-failure-bound={active_candidate.conservative_kem_failure_bound:.12g}")
    print("security-status=research screening boundary only; not a 128-bit security claim")

    return 0 if lower_candidate is None and active_candidate is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
