#!/usr/bin/env python3
"""Measure modern syndrome-decoding estimates across scaled research profiles."""

from __future__ import annotations

import argparse
import math
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_profile_audit import (
    fixed_weight_intersection_odd_probability,
    minimum_repetitions_for_kem_failure,
    sparse_witness_enumeration_bits,
)
from code_sd_estimator import estimate_upstream_isd


@dataclass(frozen=True)
class ScalePoint:
    n: int
    k: int
    weight: int


DEFAULT_POINTS = (
    ScalePoint(256, 128, 28),
    ScalePoint(512, 256, 52),
    ScalePoint(1024, 512, 104),
    ScalePoint(1536, 768, 156),
)


def _parse_point(text: str) -> ScalePoint:
    try:
        n_s, k_s, w_s = text.split(":")
        point = ScalePoint(int(n_s), int(k_s), int(w_s))
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("point must be n:k:w") from exc
    if not 0 < point.k < point.n:
        raise argparse.ArgumentTypeError("require 0 < k < n")
    if not 0 < point.weight <= point.n - point.k:
        raise argparse.ArgumentTypeError("weight must be in [1,n-k]")
    return point


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--point", action="append", type=_parse_point, default=None)
    parser.add_argument("--error-weight", type=int, default=1)
    parser.add_argument("--encapsulated-bits", type=int, default=128)
    parser.add_argument("--kem-failure-ceiling", type=float, default=1e-9)
    parser.add_argument("--max-repetitions", type=int, default=4096)
    args = parser.parse_args()

    points = tuple(args.point) if args.point else DEFAULT_POINTS
    print(
        "n,k,w,relative_weight,fastest,upstream_time_bits,upstream_memory_bits,"
        "support_enumeration_bits,effective_attack_bits,effective_attack,"
        "repetitions,cutoff,kem_failure_bound"
    )
    for point in points:
        report = estimate_upstream_isd(point.n, point.k, point.weight)
        fastest = report.fastest
        support_bits = sparse_witness_enumeration_bits(point.n, point.weight)
        effective_bits = min(fastest.time_bits, support_bits)
        effective_attack = fastest.algorithm if fastest.time_bits <= support_bits else "SupportEnumeration"

        odd_probability = fixed_weight_intersection_odd_probability(
            point.n, point.weight, args.error_weight
        )
        kem = minimum_repetitions_for_kem_failure(
            odd_probability,
            args.encapsulated_bits,
            args.kem_failure_ceiling,
            max_repetitions=args.max_repetitions,
        )
        if kem is None:
            repetitions = "NONE"
            cutoff = "NONE"
            bound = "NONE"
        else:
            repetitions = str(kem.decision.repetitions)
            cutoff = str(kem.decision.cutoff_ones)
            bound = f"{kem.conservative_union_bound:.12g}"
        memory = "n/a" if fastest.memory_bits is None else f"{fastest.memory_bits:.6f}"
        print(
            f"{point.n},{point.k},{point.weight},{point.weight/point.n:.8f},"
            f"{fastest.algorithm},{fastest.time_bits:.6f},{memory},"
            f"{support_bits:.6f},{effective_bits:.6f},{effective_attack},"
            f"{repetitions},{cutoff},{bound}"
        )
    print(
        "interpretation=effective attack screen is min(pinned upstream ISD, direct support enumeration); "
        "finite estimates only, not security proofs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
