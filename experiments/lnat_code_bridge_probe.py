#!/usr/bin/env python3
"""Correctness and witness-space probe for LNAT-CODE-BRIDGE-0."""

from __future__ import annotations

import argparse
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams, decryption_statistic
from lnat_code_bridge import (
    BRIDGE_VERSION,
    LNATCodeBridgeParams,
    decrypt_bit,
    encrypt_bit,
    keygen,
    recover_code_secret,
)
from lnat_params import LNATParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=16)
    args = parser.parse_args()
    if args.trials <= 0:
        parser.error("--trials must be positive")

    params = LNATCodeBridgeParams(
        code=CodePKEParams(
            n=64,
            k=32,
            secret_weight=2,
            encryption_error_weight=2,
            repetitions=96,
            zero_threshold=0.25,
        ),
        lnat=LNATParams(
            name="LNAT-bridge-probe",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    )

    failures = 0
    zero_stats = []
    one_stats = []
    witnesses = set()

    for trial in range(args.trials):
        pk, sk = keygen(params, rng=random.Random(50000 + trial))
        code_secret = recover_code_secret(sk, pk)
        witnesses.add(code_secret.error)

        ct0 = encrypt_bit(pk, 0, rng=random.Random(60000 + trial))
        ct1 = encrypt_bit(pk, 1, rng=random.Random(70000 + trial))
        zero_stats.append(decryption_statistic(code_secret, ct0))
        one_stats.append(decryption_statistic(code_secret, ct1))
        failures += decrypt_bit(sk, pk, ct0) != 0
        failures += decrypt_bit(sk, pk, ct1) != 1

    print(f"bridge={BRIDGE_VERSION}")
    print(f"trials={args.trials}")
    print(f"ciphertexts-tested={2 * args.trials}")
    print(f"decryption-failures={failures}")
    print(f"distinct-derived-witnesses={len(witnesses)}")
    print(f"lnat-seed-bits={params.lnat.seed_size * 8}")
    print(f"sparse-witness-space-bits={params.witness_space_bits:.6f}")
    print(f"mean-statistic-bit0={statistics.fmean(zero_stats):.6f}")
    print(f"mean-statistic-bit1={statistics.fmean(one_stats):.6f}")
    print("security-boundary=random-code decoding relation; LNAT derives witness only")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
