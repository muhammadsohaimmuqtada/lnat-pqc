#!/usr/bin/env python3
"""Assess one research profile with the maintained modern attack frontier."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import assess_modern_candidate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--weight", type=int, required=True)
    parser.add_argument("--attack-floor-bits", type=float, default=128.0)
    parser.add_argument("--error-weight", type=int, default=1)
    parser.add_argument("--encapsulated-bits", type=int, default=128)
    parser.add_argument("--kem-failure-ceiling", type=float, default=1e-9)
    parser.add_argument("--max-repetitions", type=int, default=4096)
    args = parser.parse_args()

    if args.attack_floor_bits < 0:
        parser.error("--attack-floor-bits must be non-negative")

    assessment = assess_modern_candidate(
        args.n,
        args.k,
        args.weight,
        encryption_error_weight=args.error_weight,
        encapsulated_bits=args.encapsulated_bits,
        kem_failure_ceiling=args.kem_failure_ceiling,
        max_repetitions=args.max_repetitions,
    )
    passed = assessment.passes(args.attack_floor_bits, args.kem_failure_ceiling)

    print(f"n={assessment.n}")
    print(f"k={assessment.k}")
    print(f"weight={assessment.weight}")
    print(f"upstream-package-version={assessment.upstream_package_version}")
    print(f"upstream-algorithm={assessment.upstream_algorithm}")
    print(f"upstream-time-bits={assessment.upstream_time_bits:.6f}")
    memory = "n/a" if assessment.upstream_memory_bits is None else f"{assessment.upstream_memory_bits:.6f}"
    print(f"upstream-memory-bits={memory}")
    print(f"support-enumeration-bits={assessment.support_enumeration_bits:.6f}")
    print(f"effective-attack={assessment.effective_attack}")
    print(f"effective-attack-bits={assessment.effective_attack_bits:.6f}")
    print(f"requested-attack-floor-bits={args.attack_floor_bits:.6f}")
    print(f"correctness-feasible={assessment.correctness_feasible}")
    if assessment.correctness_feasible:
        print(f"repetitions={assessment.repetitions}")
        print(f"cutoff-ones={assessment.cutoff_ones}")
        print(f"threshold={assessment.threshold:.12f}")
        print(f"modeled-seed-failure={assessment.modeled_seed_failure_probability:.12g}")
        print(f"conservative-kem-failure-bound={assessment.conservative_kem_failure_bound:.12g}")
    print(f"screen-pass={passed}")
    print("interpretation=research screening only; estimator crossing is not a security proof")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
