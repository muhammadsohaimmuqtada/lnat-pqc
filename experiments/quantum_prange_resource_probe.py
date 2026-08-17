#!/usr/bin/env python3
"""Report the paper-grounded quantum Prange resource surface for one SD point."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_quantum_prange_resources import assess_quantum_prange_resources


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--weight", type=int, required=True)
    parser.add_argument("--expect-width-qubits", type=int)
    parser.add_argument("--expect-depth-qubits", type=int)
    args = parser.parse_args()

    report = assess_quantum_prange_resources(args.n, args.k, args.weight)
    success_probability = 2.0 ** report.prange_success_log2
    grover_iterations = 2.0 ** report.grover_iteration_bits

    print(f"n={report.n}")
    print(f"k={report.k}")
    print(f"weight={report.weight}")
    print(f"paper-eprint={report.paper_eprint}")
    print(f"paper-arxiv={report.paper_arxiv}")
    print(f"reference-repository={report.reference_repository}")
    print(f"reference-commit={report.reference_commit}")
    print(f"prange-success-log2={report.prange_success_log2:.12f}")
    print(f"prange-success-probability={success_probability:.12e}")
    print(f"classical-expected-trial-bits={report.classical_expected_trial_bits:.12f}")
    print(f"idealized-grover-iteration-bits={report.grover_iteration_bits:.12f}")
    print(f"idealized-grover-iterations={grover_iterations:.12e}")
    print(f"width-optimized-logical-qubits={report.width_optimized_qubits}")
    print(f"depth-optimized-logical-qubits={report.depth_optimized_qubits}")
    print(f"width-optimized-depth-scale-bits={report.width_optimized_depth_scale_bits:.12f}")
    print(
        "interpretation=paper-grounded Prange resource surface; depth-scale is big-O "
        "with hidden constants and is not a security level or exact gate depth"
    )

    if args.expect_width_qubits is not None and report.width_optimized_qubits != args.expect_width_qubits:
        return 1
    if args.expect_depth_qubits is not None and report.depth_optimized_qubits != args.expect_depth_qubits:
        return 1
    if not all(
        math.isfinite(value)
        for value in (
            report.classical_expected_trial_bits,
            report.grover_iteration_bits,
            report.width_optimized_depth_scale_bits,
        )
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
