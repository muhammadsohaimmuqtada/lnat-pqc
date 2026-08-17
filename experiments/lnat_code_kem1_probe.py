#!/usr/bin/env python3
"""Functional/size probe for the segmented LNAT-CODE-KEM-1 harness."""

from __future__ import annotations

import argparse
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_code_kem1 import KEM1_VERSION, LNATCodeKEM1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=2)
    args = parser.parse_args()
    if args.trials <= 0:
        parser.error("--trials must be positive")

    kem = LNATCodeKEM1()
    failures = 0
    sizes = []
    keys = set()

    for trial in range(args.trials):
        pk, sk = kem.keygen(rng=random.Random(120_000 + trial))
        ct, sender = kem.encap(pk, rng=random.Random(121_000 + trial))
        try:
            receiver = kem.decap(sk, pk, ct)
        except ValueError:
            failures += 1
            continue
        failures += sender != receiver
        sizes.append(ct.size_bytes())
        keys.add(sender)

    params = kem.params
    word_bytes = (params.bridge.code.n + 7) // 8
    repetition_reference = (
        params.encapsulated_seed_bits
        * params.bridge.code.repetitions
        * word_bytes
        + params.confirmation_tag_bytes
    )
    median_size = int(statistics.median(sizes)) if sizes else 0

    print(f"profile={KEM1_VERSION}")
    print(f"trials={args.trials}")
    print(f"round-trip-failures={failures}")
    print(f"encapsulated-seed-bits={params.encapsulated_seed_bits}")
    print(f"channel-uses-per-byte={params.channel_uses_per_byte}")
    print(f"total-channel-uses={params.encapsulated_seed_bytes * params.channel_uses_per_byte}")
    print(f"ciphertext-bytes={median_size}")
    print(f"kem0-repetition-reference-bytes={repetition_reference}")
    if median_size:
        print(f"size-reduction={repetition_reference / median_size:.6f}x")
    print(f"distinct-session-keys={len(keys)}")
    print("decoder=16 independent 8-bit maximum-likelihood blocks")
    print("security-boundary=random-code decoding; research-only")
    return 0 if failures == 0 and len(keys) == args.trials else 1


if __name__ == "__main__":
    raise SystemExit(main())
