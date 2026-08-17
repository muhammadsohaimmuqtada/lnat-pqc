#!/usr/bin/env python3
"""Simple empirical probes for LNAT traces; not a security test."""

import argparse
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import lag1_agreement, make_observation, monobit_bias
from lnat_core import generate_seed
from lnat_params import LNAT128


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=64)
    args = parser.parse_args()
    if args.samples <= 0:
        parser.error("--samples must be positive")
    biases, lag1 = [], []
    for index in range(args.samples):
        obs = make_observation(
            generate_seed(LNAT128),
            LNAT128,
            nonce=index.to_bytes(16, "big"),
            seed_A=index.to_bytes(32, "big"),
            noisy=False,
        )
        biases.append(monobit_bias(obs.trace))
        lag1.append(lag1_agreement(obs.trace))
    print(f"samples={args.samples}")
    print(f"trace-bits={LNAT128.T}")
    print(f"mean-monobit-bias={statistics.fmean(biases):+.6f}")
    print(f"max-abs-monobit-bias={max(abs(x) for x in biases):.6f}")
    print(f"mean-lag1-agreement={statistics.fmean(lag1):.6f}")
    print("interpretation=measurement only; not a security claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
