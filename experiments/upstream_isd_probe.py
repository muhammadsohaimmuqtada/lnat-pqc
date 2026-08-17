#!/usr/bin/env python3
"""Cross-check one random-code profile with Crypto-TII's modern SD estimator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_sd_estimator import estimate_upstream_isd
from code_stern import best_stern_cost


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=256)
    parser.add_argument("--k", type=int, default=128)
    parser.add_argument("--weight", type=int, default=30)
    parser.add_argument("--top", type=int, default=6)
    args = parser.parse_args()
    if args.top <= 0:
        parser.error("--top must be positive")

    report = estimate_upstream_isd(args.n, args.k, args.weight)
    local_stern = best_stern_cost(args.n, args.k, args.weight)

    print(f"instance=n{args.n}-k{args.k}-w{args.weight}")
    print(f"upstream-package-version={report.package_version}")
    for rank, point in enumerate(report.points[: args.top], start=1):
        memory = "n/a" if point.memory_bits is None else f"{point.memory_bits:.3f}"
        print(
            f"rank={rank} algorithm={point.algorithm} "
            f"time-bits={point.time_bits:.3f} memory-bits={memory} "
            f"parameters={point.parameters}"
        )
    print(f"upstream-fastest={report.fastest.algorithm}")
    print(f"upstream-fastest-time-bits={report.fastest.time_bits:.3f}")
    print(f"local-stern-reference-op-bits={local_stern.estimated_total_ops_bits:.3f}")
    print("comparison-note=upstream bit-complexity and local reference-op models are not identical units")
    print("security-status=screening evidence only; not a proven security level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
