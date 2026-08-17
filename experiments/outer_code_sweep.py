#!/usr/bin/env python3
"""Sweep toy outer-code block lengths against the exact receiver channel law."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_channel_audit import code_bit_channel_capacity
from code_outer_sim import sweep_outer_code_lengths


def _parse_lengths(value: str) -> tuple[int, ...]:
    try:
        lengths = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("lengths must be comma-separated integers") from exc
    if not lengths:
        raise argparse.ArgumentTypeError("at least one length is required")
    return lengths


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--message-bits", type=int, default=8)
    parser.add_argument("--lengths", type=_parse_lengths, default=(36, 40, 44, 48, 56, 64))
    parser.add_argument("--trials-per-codebook", type=int, default=32)
    parser.add_argument("--codebooks", type=int, default=4)
    parser.add_argument("--q", type=float, default=1 / 32)
    args = parser.parse_args()
    if args.message_bits <= 0:
        parser.error("--message-bits must be positive")
    if args.trials_per_codebook <= 0:
        parser.error("--trials-per-codebook must be positive")
    if args.codebooks <= 0:
        parser.error("--codebooks must be positive")
    if not 0 <= args.q < 0.5:
        parser.error("--q must be in [0,0.5)")

    channel = code_bit_channel_capacity(args.q)
    points = sweep_outer_code_lengths(
        message_bits=args.message_bits,
        channel_uses=args.lengths,
        zero_one_probability=args.q,
        trials_per_codebook=args.trials_per_codebook,
        codebooks=args.codebooks,
    )

    print(f"q={args.q:.12f}")
    print(f"capacity-bits-per-use={channel.capacity_bits_per_use:.12f}")
    print(f"codebooks={args.codebooks}")
    print(f"trials-per-codebook={args.trials_per_codebook}")
    print("message_bits,channel_uses,rate,capacity_fraction,total_trials,failures,failure_rate")
    for point in points:
        print(
            f"{point.message_bits},{point.channel_uses},{point.rate:.12f},"
            f"{point.capacity_fraction:.12f},{point.trials},{point.failures},"
            f"{point.empirical_failure_rate:.12f}"
        )
    print("interpretation=multi-codebook finite sample only; larger Monte Carlo and structured-code analysis remain required")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
