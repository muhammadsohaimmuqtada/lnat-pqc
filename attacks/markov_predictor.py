#!/usr/bin/env python3
"""Held-out k-bit-context predictor for LNAT traces."""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import make_observation
from lnat_core import generate_seed
from lnat_params import LNAT128


def traces(count: int, offset: int):
    result = []
    for index in range(count):
        serial = offset + index
        obs = make_observation(
            generate_seed(LNAT128),
            LNAT128,
            nonce=serial.to_bytes(16, "big"),
            seed_A=serial.to_bytes(32, "big"),
            noisy=False,
        )
        result.append(obs.trace)
    return result


def train(data, k: int):
    counts = defaultdict(lambda: [0, 0])
    global_counts = [0, 0]
    for trace in data:
        for i in range(k, len(trace)):
            ctx, bit = tuple(trace[i - k : i]), trace[i]
            counts[ctx][bit] += 1
            global_counts[bit] += 1
    fallback = 1 if global_counts[1] > global_counts[0] else 0
    return {ctx: 1 if c[1] > c[0] else 0 for ctx, c in counts.items()}, fallback


def evaluate(data, model, fallback: int, k: int):
    correct = total = ones = 0
    for trace in data:
        for i in range(k, len(trace)):
            bit = trace[i]
            pred = model.get(tuple(trace[i - k : i]), fallback)
            correct += pred == bit
            ones += bit
            total += 1
    return correct / total, max(ones, total - ones) / total, total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", type=int, default=64)
    parser.add_argument("--test", type=int, default=32)
    parser.add_argument("-k", type=int, default=4)
    args = parser.parse_args()
    if args.train <= 0 or args.test <= 0 or args.k <= 0:
        parser.error("train/test/k must be positive")
    model, fallback = train(traces(args.train, 1), args.k)
    accuracy, baseline, total = evaluate(traces(args.test, 100000), model, fallback, args.k)
    print(f"train-traces={args.train}")
    print(f"test-traces={args.test}")
    print(f"context-bits={args.k}")
    print(f"held-out-bits={total}")
    print(f"predictor-accuracy={accuracy:.6f}")
    print(f"majority-baseline={baseline:.6f}")
    print(f"advantage={accuracy - baseline:+.6f}")
    print("interpretation=empirical probe only; not a security proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
