#!/usr/bin/env python3
"""Report finite proof-component costs for Punctured/Combined-Hybrid ISD."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_punctured_combined_hybrid import (
    assess_combined_hybrid,
    optimize_punctured_weight,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--weight", type=int, required=True)
    parser.add_argument("--guess-zeros", type=int, default=0)
    parser.add_argument("--omit", type=int, required=True)
    parser.add_argument("--p", type=int)
    args = parser.parse_args()

    if args.p is None:
        report = optimize_punctured_weight(
            args.n, args.k, args.weight, args.guess_zeros, args.omit
        )
    else:
        report = assess_combined_hybrid(
            args.n, args.k, args.weight, args.guess_zeros, args.omit, args.p
        )

    print(f"point={report.n}:{report.k}:{report.weight}")
    print(f"guessed-zero-positions={report.guessed_zero_positions}")
    print(f"omitted-parity-equations={report.omitted_parity_equations}")
    print(f"punctured-weight={report.punctured_weight}")
    print(f"reduced-instance={report.reduced_length}:{report.reduced_dimension}:{report.reduced_weight}")
    print(f"reduced-parity-checks={report.reduced_parity_checks}")
    print(f"matrix-representation-qubits={report.matrix_representation_qubits}")
    print(f"matrix-memory-fraction={report.matrix_memory_fraction:.12f}")
    print(f"log2-correct-zero-guess-probability={report.log2_correct_zero_guess_probability:.12f}")
    print(f"log2-expected-outer-iterations={report.log2_expected_outer_iterations:.12f}")
    print(f"log2-expected-reduced-solutions={report.log2_expected_reduced_solutions:.12f}")
    print(f"log2-repeat-factor={report.log2_repeat_factor:.12f}")
    print(f"log2-quantum-subroutine-proxy={report.log2_quantum_subroutine_proxy:.12f}")
    print(f"proof-time-proxy-bits={report.proof_time_proxy_bits:.12f}")
    print(
        "interpretation=log2 of explicit theorem proof factors up to soft-O polynomial/hidden "
        "constants; not a finite gate count or security level"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
