#!/usr/bin/env python3
"""Measure full-rank generator construction at the current research geometry."""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import gf2_rank, random_full_rank_code


def main() -> int:
    n = 1064
    k = 532
    started = time.perf_counter()
    rows = random_full_rank_code(n, k, rng=random.Random(1064))
    elapsed = time.perf_counter() - started
    rank = gf2_rank(rows, n)
    print(f"n={n}")
    print(f"k={k}")
    print(f"rows={len(rows)}")
    print(f"rank={rank}")
    print(f"elapsed-seconds={elapsed:.6f}")
    print("implementation=incremental triangular GF2 rank basis")
    return 0 if len(rows) == k and rank == k else 1


if __name__ == "__main__":
    raise SystemExit(main())
