#!/usr/bin/env python3
"""Recover the toy bridge's sparse witness using public data only."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_attacks import recover_sparse_error_from_public_key
from code_pke_reference import CodePKEParams, CodePKESecretKey, decrypt_bit
from lnat_code_bridge import (
    LNATCodeBridgeParams,
    encrypt_bit,
    keygen,
    recover_code_secret,
)
from lnat_params import LNATParams


def main() -> int:
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
            name="LNAT-bridge-public-attack",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    )

    pk, sk = keygen(params, rng=random.Random(81001))
    legitimate = recover_code_secret(sk, pk)

    # Everything below the recovery call uses public information only.
    recovery = recover_sparse_error_from_public_key(pk.code_key)
    attacker_secret = CodePKESecretKey(recovery.witness, params.code)

    ct0 = encrypt_bit(pk, 0, rng=random.Random(82000))
    ct1 = encrypt_bit(pk, 1, rng=random.Random(82001))
    recovered0 = decrypt_bit(attacker_secret, ct0)
    recovered1 = decrypt_bit(attacker_secret, ct1)

    exact = recovery.witness == legitimate.error
    success = exact and recovered0 == 0 and recovered1 == 1

    print("attack=public sparse-witness enumeration")
    print(f"lnat-seed-bits={params.lnat.seed_size * 8}")
    print(f"witness-space-bits={params.witness_space_bits:.6f}")
    print(f"total-candidates={recovery.total_candidates}")
    print(f"candidates-tested={recovery.candidates_tested}")
    print(f"search-fraction={recovery.search_fraction:.6f}")
    print(f"exact-witness-recovered={exact}")
    print(f"decrypt-bit0={recovered0}")
    print(f"decrypt-bit1={recovered1}")
    print(f"attack-success={success}")
    print("interpretation=toy bridge is bounded by sparse-code witness space, not LNAT seed length")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
