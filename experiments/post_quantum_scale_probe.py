#!/usr/bin/env python3
"""Measure classical + quantum-baseline + correctness gates for code points."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_post_quantum_frontier import assess_post_quantum_candidate


def parse_point(text: str) -> tuple[int, int, int]:
    try:
        n_text, k_text, w_text = text.split(":")
        point = (int(n_text), int(k_text), int(w_text))
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("point must be n:k:w") from exc
    n, k, w = point
    if not 0 < k < n or not 0 < w <= n:
        raise argparse.ArgumentTypeError("require 0 < k < n and 0 < w <= n")
    return point


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--point", action="append", type=parse_point, required=True)
    parser.add_argument("--classical-floor-bits", type=float, default=128.0)
    parser.add_argument("--quantum-floor-bits", type=float, default=128.0)
    parser.add_argument("--error-weight", type=int, default=1)
    parser.add_argument("--encapsulated-bits", type=int, default=128)
    parser.add_argument("--kem-failure-ceiling", type=float, default=1e-9)
    parser.add_argument("--max-repetitions", type=int, default=512)
    args = parser.parse_args()

    for n, k, weight in args.point:
        assessment = assess_post_quantum_candidate(
            n,
            k,
            weight,
            encryption_error_weight=args.error_weight,
            encapsulated_bits=args.encapsulated_bits,
            kem_failure_ceiling=args.kem_failure_ceiling,
            max_repetitions=args.max_repetitions,
        )
        classical = assessment.classical
        quantum = assessment.quantum
        passed = assessment.passes(
            classical_attack_floor_bits=args.classical_floor_bits,
            quantum_iteration_floor_bits=args.quantum_floor_bits,
            kem_failure_ceiling=args.kem_failure_ceiling,
        )

        print(f"point={n}:{k}:{weight}")
        print(f"classical-upstream-package={classical.upstream_package_version}")
        print(f"classical-fastest={classical.upstream_algorithm}")
        print(f"classical-upstream-time-bits={classical.upstream_time_bits:.12f}")
        print(f"classical-effective-attack={classical.effective_attack}")
        print(f"classical-effective-bits={classical.effective_attack_bits:.12f}")
        print(f"support-enumeration-bits={classical.support_enumeration_bits:.12f}")
        print(f"quantum-baseline-attack={quantum.effective_quantum_search_attack}")
        print(f"quantum-baseline-bits={quantum.effective_quantum_search_bits:.12f}")
        print(f"grover-prange-bits={quantum.grover_prange_iteration_bits:.12f}")
        print(f"grover-support-bits={quantum.grover_support_iteration_bits:.12f}")
        print(f"correctness-feasible={classical.correctness_feasible}")
        if classical.correctness_feasible:
            print(f"repetitions={classical.repetitions}")
            print(f"cutoff-ones={classical.cutoff_ones}")
            print(f"conservative-kem-failure-bound={classical.conservative_kem_failure_bound:.12g}")
        print(f"classical-floor-bits={args.classical_floor_bits:.12f}")
        print(f"quantum-floor-bits={args.quantum_floor_bits:.12f}")
        print(f"combined-screen-pass={passed}")
        print(
            "interpretation=research screen only; quantum component is a rejection "
            "baseline, not best-known quantum security"
        )
        print()

    # Measurement mode deliberately succeeds even when candidates are rejected.
    # The printed pass/fail field is the result; CI should not promote a point
    # merely because this process exits successfully.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
