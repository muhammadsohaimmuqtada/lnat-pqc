#!/usr/bin/env python3
"""Report necessary correctness and public-attack guards for code profiles."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams
from code_profile_audit import audit_code_profile, minimum_weight_for_trivial_floor


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=64)
    parser.add_argument("--k", type=int, default=32)
    parser.add_argument("--secret-weight", type=int, default=2)
    parser.add_argument("--error-weight", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=96)
    parser.add_argument("--threshold", type=float, default=0.25)
    parser.add_argument(
        "--trivial-floor-bits",
        type=float,
        default=None,
        help="optional necessary floor for full witness enumeration only",
    )
    parser.add_argument(
        "--prange-trial-floor-bits",
        type=float,
        default=None,
        help="optional floor for log2 expected Prange information-set trials only",
    )
    args = parser.parse_args()

    params = CodePKEParams(
        n=args.n,
        k=args.k,
        secret_weight=args.secret_weight,
        encryption_error_weight=args.error_weight,
        repetitions=args.repetitions,
        zero_threshold=args.threshold,
    )
    audit = audit_code_profile(params)

    print(f"n={params.n}")
    print(f"k={params.k}")
    print(f"secret-weight={params.secret_weight}")
    print(f"encryption-error-weight={params.encryption_error_weight}")
    print(f"witness-space-size={audit.witness_space_size}")
    print(f"trivial-enumeration-bits={audit.trivial_enumeration_bits:.6f}")
    print(f"prange-expected-information-sets={audit.prange_expected_information_sets:.6f}")
    print(f"prange-expected-trial-bits={audit.prange_expected_trial_bits:.6f}")
    print(f"enc0-one-probability={audit.zero_inner_product_one_probability:.12g}")
    print(f"decision-cutoff-ones={audit.decision_cutoff_ones}")
    print(f"bit0-failure-probability={audit.bit0_failure_probability:.12g}")
    print(f"bit1-failure-probability={audit.bit1_failure_probability:.12g}")
    print(f"worst-bit-failure-probability={audit.worst_bit_failure_probability:.12g}")

    if args.trivial_floor_bits is not None:
        meets = audit.meets_trivial_enumeration_floor(args.trivial_floor_bits)
        minimum = minimum_weight_for_trivial_floor(params.n, args.trivial_floor_bits)
        print(f"requested-trivial-floor-bits={args.trivial_floor_bits:.6f}")
        print(f"meets-trivial-floor={meets}")
        print(f"minimum-weight-for-floor={minimum}")

    if args.prange_trial_floor_bits is not None:
        meets = audit.meets_prange_trial_floor(args.prange_trial_floor_bits)
        print(f"requested-prange-trial-floor-bits={args.prange_trial_floor_bits:.6f}")
        print(f"meets-prange-trial-floor={meets}")

    print("interpretation=necessary attack/correctness guards only; Prange trial count omits polynomial per-trial cost")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
