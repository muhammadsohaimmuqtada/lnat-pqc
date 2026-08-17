#!/usr/bin/env python3
"""Exhaustive seed recovery baseline for deliberately tiny LNAT profiles."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import exhaustive_seed_recovery, make_observation
from lnat_params import LNATParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-bits", choices=("8", "16"), default="8")
    parser.add_argument("--traces", type=int, default=3)
    parser.add_argument("--noise", type=float, default=0.05)
    parser.add_argument("--secret", default=None)
    args = parser.parse_args()
    if args.traces <= 0:
        parser.error("--traces must be positive")
    if not 0 <= args.noise <= 1:
        parser.error("--noise must be in [0,1]")
    seed_size = int(args.seed_bits) // 8
    params = LNATParams(
        name=f"LNAT-attack-seed{args.seed_bits}",
        n=8 if seed_size == 1 else 12,
        m=2,
        T=32,
        eta=args.noise,
        seed_size=seed_size,
    )
    default_seed = b"\xa7" if seed_size == 1 else bytes.fromhex("beef")
    secret = bytes.fromhex(args.secret) if args.secret else default_seed
    if len(secret) != seed_size:
        parser.error(f"secret must be exactly {seed_size} byte(s)")
    observations = [
        make_observation(
            secret,
            params,
            nonce=bytes([index + 1]) * 8,
            seed_A=bytes([0x40 + index]) * 32,
            noisy=args.noise > 0,
            rng=random.Random(1000 + index),
        )
        for index in range(args.traces)
    ]
    recovered, score, tested = exhaustive_seed_recovery(observations, params)
    print(f"profile={params.name}")
    print(f"secret={secret.hex()}")
    print(f"recovered={recovered.hex()}")
    print(f"hamming-score={score}")
    print(f"candidates-tested={tested}")
    print(f"success={recovered == secret}")
    return 0 if recovered == secret else 1


if __name__ == "__main__":
    raise SystemExit(main())
