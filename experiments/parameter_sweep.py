#!/usr/bin/env python3
"""Generate machine-readable trace statistics across research profiles."""

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import lag1_agreement, make_observation, monobit_bias
from lnat_core import generate_seed
from lnat_params import LNAT128, LNAT192, LNAT256


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=16)
    parser.add_argument("--output", default="-")
    args = parser.parse_args()
    if args.samples <= 0:
        parser.error("--samples must be positive")
    rows = []
    for profile in (LNAT128, LNAT192, LNAT256):
        for sample in range(args.samples):
            serial = (profile.n << 32) | sample
            obs = make_observation(
                generate_seed(profile),
                profile,
                nonce=serial.to_bytes(16, "big"),
                seed_A=serial.to_bytes(32, "big"),
                noisy=False,
            )
            rows.append({
                "profile": profile.name,
                "sample": sample,
                "n": profile.n,
                "m": profile.m,
                "T": profile.T,
                "monobit_bias": f"{monobit_bias(obs.trace):.8f}",
                "lag1_agreement": f"{lag1_agreement(obs.trace):.8f}",
            })
    fields = list(rows[0])
    if args.output == "-":
        writer = csv.DictWriter(sys.stdout, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    else:
        with open(args.output, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
