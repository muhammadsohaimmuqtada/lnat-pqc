#!/usr/bin/env python3
"""Correctness probe for the toy Alekhnovich-style reference PKE."""

from __future__ import annotations

import argparse
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import (
    CodePKEParams,
    decrypt_bit,
    decryption_statistic,
    encrypt_bit,
    keygen,
    public_secret_orthogonality_holds,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=32)
    args = parser.parse_args()
    if args.trials <= 0:
        parser.error("--trials must be positive")

    params = CodePKEParams(
        n=64,
        k=32,
        secret_weight=2,
        encryption_error_weight=2,
        repetitions=96,
        zero_threshold=0.25,
    )

    failures = 0
    zero_stats = []
    one_stats = []
    relation_failures = 0

    for trial in range(args.trials):
        pk, sk = keygen(params, rng=random.Random(10000 + trial))
        relation_failures += not public_secret_orthogonality_holds(pk, sk)
        ct0 = encrypt_bit(pk, 0, rng=random.Random(20000 + trial))
        ct1 = encrypt_bit(pk, 1, rng=random.Random(30000 + trial))
        zero_stats.append(decryption_statistic(sk, ct0))
        one_stats.append(decryption_statistic(sk, ct1))
        failures += decrypt_bit(sk, ct0) != 0
        failures += decrypt_bit(sk, ct1) != 1

    print(f"trials={args.trials}")
    print(f"ciphertexts-tested={2 * args.trials}")
    print(f"decryption-failures={failures}")
    print(f"relation-failures={relation_failures}")
    print(f"mean-statistic-bit0={statistics.fmean(zero_stats):.6f}")
    print(f"mean-statistic-bit1={statistics.fmean(one_stats):.6f}")
    print(f"threshold={params.zero_threshold:.6f}")
    print("status=toy random-code PKE comparator; no LNAT security claim")
    return 0 if failures == 0 and relation_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
