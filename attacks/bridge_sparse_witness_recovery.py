#!/usr/bin/env python3
"""Recover the toy bridge's sparse witness using public data only."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_attacks import (
    prange_expected_information_sets,
    prange_expected_trial_bits,
    recover_sparse_error_from_public_key,
    recover_sparse_error_prange,
)
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

    # Both recovery paths below use only the public random-code instance.
    enumeration = recover_sparse_error_from_public_key(pk.code_key)
    prange = recover_sparse_error_prange(
        pk.code_key,
        rng=random.Random(83000),
        max_subsets=512,
    )

    attacker_secret = CodePKESecretKey(prange.witness, params.code)
    ct0 = encrypt_bit(pk, 0, rng=random.Random(82000))
    ct1 = encrypt_bit(pk, 1, rng=random.Random(82001))
    recovered0 = decrypt_bit(attacker_secret, ct0)
    recovered1 = decrypt_bit(attacker_secret, ct1)

    enumeration_exact = enumeration.witness == legitimate.error
    prange_exact = prange.witness == legitimate.error
    success = enumeration_exact and prange_exact and recovered0 == 0 and recovered1 == 1

    expected_trials = prange_expected_information_sets(
        params.code.n,
        params.code.k,
        params.code.secret_weight,
    )
    expected_trial_bits = prange_expected_trial_bits(
        params.code.n,
        params.code.k,
        params.code.secret_weight,
    )

    print("attack=public decoding of toy LNAT code bridge")
    print(f"lnat-seed-bits={params.lnat.seed_size * 8}")
    print(f"witness-space-bits={params.witness_space_bits:.6f}")
    print(f"enumeration-total-candidates={enumeration.total_candidates}")
    print(f"enumeration-candidates-tested={enumeration.candidates_tested}")
    print(f"enumeration-search-fraction={enumeration.search_fraction:.6f}")
    print(f"prange-expected-information-sets={expected_trials:.6f}")
    print(f"prange-expected-trial-bits={expected_trial_bits:.6f}")
    print(f"prange-subsets-sampled={prange.subsets_sampled}")
    print(f"prange-invertible-subsets={prange.invertible_subsets}")
    print(f"enumeration-exact-witness={enumeration_exact}")
    print(f"prange-exact-witness={prange_exact}")
    print(f"decrypt-bit0={recovered0}")
    print(f"decrypt-bit1={recovered1}")
    print(f"attack-success={success}")
    print("interpretation=Prange-style decoding is a stronger public attack baseline than full witness enumeration")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
