#!/usr/bin/env python3
"""Recover the toy LNAT-CODE-KEM-0 session key using only public data."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_kem_attacks import recover_code_kem_from_public_data
from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem import KEM_VERSION, LNATCodeKEM0, LNATCodeKEMParams
from lnat_params import LNATParams


def main() -> int:
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
                name="LNAT-code-kem-public-break",
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
    pk, _ = kem.keygen(rng=random.Random(93001))
    ct, legitimate = kem.encap(pk, rng=random.Random(93002))

    recovered = recover_code_kem_from_public_data(
        pk,
        ct,
        rng=random.Random(93003),
        max_subsets=512,
    )
    success = recovered.session_key == legitimate

    print(f"profile={KEM_VERSION}")
    print("attack=public Prange witness recovery followed by public decapsulation")
    print(f"lnat-secret-required=False")
    print(f"prange-subsets-sampled={recovered.prange_subsets_sampled}")
    print(f"prange-invertible-subsets={recovered.prange_invertible_subsets}")
    print(f"encapsulated-seed-bytes={len(recovered.encapsulated_seed)}")
    print(f"session-key-bytes={len(recovered.session_key)}")
    print(f"exact-session-key-recovered={success}")
    print("interpretation=toy KEM inherits the public code-decoding weakness; LNAT seed recovery is unnecessary")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
