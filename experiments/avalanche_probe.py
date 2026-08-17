#!/usr/bin/env python3
"""Measure what the LNAT state chain adds over a direct keyed PRF stream."""

from __future__ import annotations

import argparse
import hashlib
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import input_avalanche
from lnat_params import ALL_PARAMS, DEFAULT_PARAMS


def derive(label: bytes, index: int, length: int) -> bytes:
    return hashlib.shake_256(label + index.to_bytes(8, "big")).digest(length)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--profile", choices=sorted(ALL_PARAMS), default=DEFAULT_PARAMS.name)
    args = parser.parse_args()
    if args.samples <= 0:
        parser.error("--samples must be positive")

    params = ALL_PARAMS[args.profile]
    lnat_rates = []
    mutation_changes = 0
    direct_mutation_changes = 0

    for index in range(args.samples):
        seed = derive(b"LNAT-AVALANCHE-SEED|", index, params.seed_size)
        nonce = derive(b"LNAT-AVALANCHE-NONCE|", index, 16)
        seed_a = derive(b"LNAT-AVALANCHE-INPUT|", index, 32)
        mutation_index = (params.T // 4 + index * 17) % (params.T - 1)
        result = input_avalanche(
            seed,
            params,
            nonce=nonce,
            seed_A=seed_a,
            mutation_index=mutation_index,
        )
        if result.direct_tail_differences != 0:
            print("error=direct baseline propagated beyond mutated step")
            return 1
        lnat_rates.append(result.lnat_tail_rate)
        mutation_changes += int(result.lnat_mutation_bit_changed)
        direct_mutation_changes += int(result.direct_mutation_bit_changed)

    print(f"profile={params.name}")
    print(f"samples={args.samples}")
    print(f"lnat-mean-tail-divergence={statistics.fmean(lnat_rates):.6f}")
    print(f"lnat-min-tail-divergence={min(lnat_rates):.6f}")
    print(f"lnat-max-tail-divergence={max(lnat_rates):.6f}")
    print(f"lnat-mutation-bit-change-rate={mutation_changes / args.samples:.6f}")
    print(f"direct-mutation-bit-change-rate={direct_mutation_changes / args.samples:.6f}")
    print("direct-tail-divergence=0.000000")
    print("interpretation=state-chain propagation observed; this is not a security claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
