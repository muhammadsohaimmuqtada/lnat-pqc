#!/usr/bin/env python3
"""Screen code research profiles against necessary attack/full-KEM correctness gates."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_profile_audit import screen_necessary_kem_candidate


def _print_candidate(
    candidate,
    *,
    requested_trial_bits: float,
    kem_failure_ceiling: float,
) -> None:
    print(f"n={candidate.n}")
    print(f"k={candidate.k}")
    print(f"secret-weight={candidate.secret_weight}")
    print(f"encryption-error-weight={candidate.encryption_error_weight}")
    print(f"requested-prange-trial-floor-bits={requested_trial_bits:.6f}")
    print(f"prange-expected-trial-bits={candidate.prange_expected_trial_bits:.6f}")
    print(f"full-witness-enumeration-bits={candidate.full_witness_enumeration_bits:.6f}")
    print(f"encapsulated-bits={candidate.encapsulated_bits}")
    print(f"repetitions={candidate.repetitions}")
    print(f"cutoff-ones={candidate.cutoff_ones}")
    print(f"threshold={candidate.threshold:.12f}")
    print(f"bit0-failure-probability={candidate.bit0_failure_probability:.12g}")
    print(f"bit1-failure-probability={candidate.bit1_failure_probability:.12g}")
    print(f"modeled-seed-failure-probability={candidate.modeled_seed_failure_probability:.12g}")
    print(f"conservative-kem-failure-bound={candidate.conservative_kem_failure_bound:.12g}")
    print(f"requested-kem-failure-ceiling={kem_failure_ceiling:.12g}")
    print("interpretation=necessary screening point only; not a security parameter recommendation")


def _grid(
    error_weight: int,
    encapsulated_bits: int,
    kem_failure_ceiling: float,
    max_repetitions: int,
) -> int:
    print(
        "n,k,requested_prange_bits,weight,actual_prange_bits,encapsulated_bits,"
        "repetitions,cutoff,modeled_seed_failure,conservative_kem_bound"
    )
    for n in (256, 512, 1024):
        k = n // 2
        for requested in (32.0, 64.0, 96.0, 128.0):
            candidate = screen_necessary_kem_candidate(
                n=n,
                k=k,
                prange_trial_floor_bits=requested,
                encryption_error_weight=error_weight,
                encapsulated_bits=encapsulated_bits,
                kem_failure_ceiling=kem_failure_ceiling,
                max_repetitions=max_repetitions,
            )
            if candidate is None:
                print(
                    f"{n},{k},{requested:.0f},NONE,NONE,{encapsulated_bits},"
                    "NONE,NONE,NONE,NONE"
                )
                continue
            print(
                f"{n},{k},{requested:.0f},{candidate.secret_weight},"
                f"{candidate.prange_expected_trial_bits:.6f},"
                f"{candidate.encapsulated_bits},{candidate.repetitions},"
                f"{candidate.cutoff_ones},"
                f"{candidate.modeled_seed_failure_probability:.12g},"
                f"{candidate.conservative_kem_failure_bound:.12g}"
            )
    print("interpretation=necessary screening frontier only; stronger ISD analysis still required")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=256)
    parser.add_argument("--k", type=int, default=128)
    parser.add_argument("--prange-trial-bits", type=float, default=32.0)
    parser.add_argument("--error-weight", type=int, default=1)
    parser.add_argument("--encapsulated-bits", type=int, default=128)
    parser.add_argument("--kem-failure-ceiling", type=float, default=1e-9)
    parser.add_argument("--max-repetitions", type=int, default=1024)
    parser.add_argument("--grid", action="store_true")
    args = parser.parse_args()

    if args.grid:
        return _grid(
            args.error_weight,
            args.encapsulated_bits,
            args.kem_failure_ceiling,
            args.max_repetitions,
        )

    candidate = screen_necessary_kem_candidate(
        n=args.n,
        k=args.k,
        prange_trial_floor_bits=args.prange_trial_bits,
        encryption_error_weight=args.error_weight,
        encapsulated_bits=args.encapsulated_bits,
        kem_failure_ceiling=args.kem_failure_ceiling,
        max_repetitions=args.max_repetitions,
    )
    if candidate is None:
        print("candidate=NONE")
        print("interpretation=no profile met the requested necessary filters within the search limits")
        return 1

    _print_candidate(
        candidate,
        requested_trial_bits=args.prange_trial_bits,
        kem_failure_ceiling=args.kem_failure_ceiling,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
