#!/usr/bin/env python3
"""Report engineering footprint of the measured modern research profile."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_candidate_profiles import MODERN_128_SCREEN_V1


def main() -> int:
    profile = MODERN_128_SCREEN_V1
    print(f"profile={profile.name}")
    print(f"n={profile.n}")
    print(f"k={profile.k}")
    print(f"secret-weight={profile.secret_weight}")
    print(f"repetitions={profile.repetitions}")
    print(f"cutoff-ones={profile.cutoff_ones}")
    print(f"threshold={profile.threshold:.12f}")
    print(f"measured-effective-attack-bits={profile.measured_effective_attack_bits:.6f}")
    print(f"estimator={profile.estimator_algorithm}@{profile.estimator_version}")
    print(f"conservative-kem-failure-bound={profile.conservative_kem_failure_bound:.12g}")
    print(f"word-bytes={profile.word_bytes}")
    print(f"generator-bytes={profile.generator_bytes}")
    print(f"raw-public-code-bytes={profile.raw_public_code_bytes}")
    print(f"public-context-bytes={profile.public_context_bytes}")
    print(f"private-seed-bytes={profile.private_seed_bytes}")
    print(f"ciphertext-body-bytes={profile.ciphertext_body_bytes}")
    print(f"ciphertext-bytes={profile.ciphertext_bytes}")
    print(f"ciphertext-mib={profile.ciphertext_bytes / (1024 * 1024):.6f}")
    print("engineering-status=bandwidth-heavy research candidate; not deployment-ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
