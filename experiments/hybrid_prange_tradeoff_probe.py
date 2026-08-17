#!/usr/bin/env python3
"""Report Hybrid-Prange matrix-memory/time trade-offs for one code point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_hybrid_prange_tradeoff import assess_hybrid_prange_tradeoff


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--weight", type=int, required=True)
    parser.add_argument("--guess-zeros", action="append", type=int, required=True)
    args = parser.parse_args()

    for guessed in args.guess_zeros:
        report = assess_hybrid_prange_tradeoff(
            args.n,
            args.k,
            args.weight,
            guessed,
        )
        print(f"point={report.n}:{report.k}:{report.weight}")
        print(f"guessed-zero-positions={report.guessed_zero_positions}")
        print(f"retained-quantum-dimension={report.retained_quantum_dimension}")
        print(f"delta={report.qubit_fraction_delta:.12f}")
        print(f"reduced-instance={report.reduced_n}:{report.reduced_k}:{report.reduced_weight}")
        print(f"matrix-representation-qubits={report.matrix_representation_qubits}")
        print(f"full-matrix-representation-qubits={report.full_matrix_representation_qubits}")
        print(f"matrix-memory-fraction={report.matrix_memory_fraction:.12f}")
        print(f"matrix-memory-reduction={report.matrix_memory_reduction_fraction:.12f}")
        print(f"hybrid-time-exponent={report.time_exponent:.12f}")
        print(f"paper-eprint={report.paper_eprint}")
        print(f"reference-repository={report.reference_repository}")
        print(f"reference-commit={report.reference_commit}")
        print(
            "interpretation=Theorem-1 asymptotic time exponent and matrix-memory term; "
            "not total circuit width, gate count, or security level"
        )
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
