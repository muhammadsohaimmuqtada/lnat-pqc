#!/usr/bin/env python3
"""Recover the default LNAT-CODE-KEM-1 session key using public data only."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_kem1_attacks import recover_kem1_from_public_data
from lnat_code_kem1 import KEM1_VERSION, LNATCodeKEM1


def main() -> int:
    kem = LNATCodeKEM1()
    pk, _ = kem.keygen(rng=random.Random(130_001))
    ct, legitimate = kem.encap(pk, rng=random.Random(130_002))
    recovered = recover_kem1_from_public_data(
        pk,
        ct,
        rng=random.Random(130_003),
        max_subsets=10_000,
    )
    success = recovered.session_key == legitimate

    print(f"profile={KEM1_VERSION}")
    print("attack=public Prange witness recovery plus segmented outer-code decapsulation")
    print("lnat-secret-required=False")
    print(f"prange-subsets-sampled={recovered.prange_subsets_sampled}")
    print(f"prange-invertible-subsets={recovered.prange_invertible_subsets}")
    print(f"encapsulated-seed-bytes={len(recovered.encapsulated_seed)}")
    print(f"session-key-bytes={len(recovered.session_key)}")
    print(f"exact-session-key-recovered={success}")
    print("interpretation=KEM-1 improves efficiency but inherits the same public code-decoding weakness")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
