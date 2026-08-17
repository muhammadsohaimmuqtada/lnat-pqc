#!/usr/bin/env python3
"""Probe transparent Groverized ISD search exponents for one research point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_quantum_isd import assess_quantum_isd


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--weight", type=int, required=True)
    parser.add_argument("--iteration-floor-bits", type=float, default=128.0)
    parser.add_argument(
        "--expect",
        choices=("pass", "reject", "any"),
        default="any",
        help="make the probe fail only if the modeled result disagrees with this expectation",
    )
    args = parser.parse_args()

    report = assess_quantum_isd(args.n, args.k, args.weight)
    passed = report.passes_iteration_floor(args.iteration_floor_bits)

    print(f"n={report.n}")
    print(f"k={report.k}")
    print(f"weight={report.weight}")
    print(f"classical-prange-trial-bits={report.classical_prange_trial_bits:.12f}")
    print(f"grover-prange-iteration-bits={report.grover_prange_iteration_bits:.12f}")
    print(
        "classical-support-enumeration-bits="
        f"{report.classical_support_enumeration_bits:.12f}"
    )
    print(f"grover-support-iteration-bits={report.grover_support_iteration_bits:.12f}")
    print(f"effective-quantum-search={report.effective_quantum_search_attack}")
    print(f"effective-quantum-search-bits={report.effective_quantum_search_bits:.12f}")
    print(f"requested-iteration-floor-bits={args.iteration_floor_bits:.12f}")
    print(f"screen-pass={passed}")
    print(
        "interpretation=quantum search iterations only; excludes reversible-oracle gate cost "
        "and stronger quantum ISD"
    )

    if args.expect == "pass" and not passed:
        return 1
    if args.expect == "reject" and passed:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
