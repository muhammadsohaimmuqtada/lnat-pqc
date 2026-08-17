#!/usr/bin/env python3
"""Run one deterministic full-size round trip for the measured research profile."""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_candidate_profiles import MODERN_128_SCREEN_V1
from lnat_code_kem import LNATCodeKEM0


def main() -> int:
    profile = MODERN_128_SCREEN_V1
    kem = LNATCodeKEM0(profile.to_kem_params())
    rng = random.Random(0x1064_532_117)

    started = time.perf_counter()
    pk, sk = kem.keygen(rng=rng)
    keygen_seconds = time.perf_counter() - started

    started = time.perf_counter()
    ct, sender_key = kem.encap(pk, rng=rng)
    encap_seconds = time.perf_counter() - started

    started = time.perf_counter()
    receiver_key = kem.decap(sk, pk, ct)
    decap_seconds = time.perf_counter() - started

    matched = sender_key == receiver_key
    expected_size = profile.ciphertext_bytes
    actual_size = ct.size_bytes()

    print(f"profile={profile.name}")
    print(f"round-trip={matched}")
    print(f"key-bytes={len(sender_key)}")
    print(f"ciphertext-bytes={actual_size}")
    print(f"expected-ciphertext-bytes={expected_size}")
    print(f"keygen-seconds={keygen_seconds:.6f}")
    print(f"encap-seconds={encap_seconds:.6f}")
    print(f"decap-seconds={decap_seconds:.6f}")
    print(f"total-seconds={keygen_seconds + encap_seconds + decap_seconds:.6f}")
    print("status=full-size research mechanics only; no security/deployment claim")
    return 0 if matched and actual_size == expected_size else 1


if __name__ == "__main__":
    raise SystemExit(main())
