#!/usr/bin/env python3
"""Functional probe for LNAT-CODE-KEM-0 on deliberately small parameters."""

from __future__ import annotations

import argparse
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem import KEM_VERSION, LNATCodeKEM0, LNATCodeKEMParams
from lnat_params import LNATParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=8)
    args = parser.parse_args()
    if args.trials <= 0:
        parser.error("--trials must be positive")

    params = LNATCodeKEMParams(
        bridge=LNATCodeBridgeParams(
            code=CodePKEParams(
                n=64,
                k=32,
                secret_weight=2,
                encryption_error_weight=1,
                repetitions=96,
                zero_threshold=0.25,
            ),
            lnat=LNATParams(
                name="LNAT-code-kem-probe",
                n=32,
                m=4,
                T=32,
                eta=0.0,
                seed_size=32,
            ),
        ),
        encapsulated_seed_bytes=2,
        confirmation_tag_bytes=16,
    )
    kem = LNATCodeKEM0(params)

    failures = 0
    ciphertext_sizes = []
    distinct_keys = set()
    for trial in range(args.trials):
        pk, sk = kem.keygen(rng=random.Random(90000 + trial))
        ct, sender = kem.encap(pk, rng=random.Random(91000 + trial))
        try:
            receiver = kem.decap(sk, pk, ct)
        except ValueError:
            failures += 1
            continue
        failures += sender != receiver
        ciphertext_sizes.append(ct.size_bytes())
        distinct_keys.add(sender)

    print(f"profile={KEM_VERSION}")
    print(f"trials={args.trials}")
    print(f"round-trip-failures={failures}")
    print(f"encapsulated-seed-bits={params.encapsulated_seed_bits}")
    print(f"shared-key-bytes=32")
    print(f"distinct-session-keys={len(distinct_keys)}")
    if ciphertext_sizes:
        print(f"ciphertext-bytes={int(statistics.median(ciphertext_sizes))}")
    print("security-boundary=random-code decoding; functional research KEM only")
    print("production-path=LNAT-MLKEM768-HYBRID-v1")
    return 0 if failures == 0 and len(distinct_keys) == args.trials else 1


if __name__ == "__main__":
    raise SystemExit(main())
