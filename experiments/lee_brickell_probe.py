#!/usr/bin/env python3
"""Compare executable Prange/Lee-Brickell recovery and model a larger profile."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_isd import best_lee_brickell_cost, recover_sparse_error_lee_brickell
from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)


def main() -> int:
    params = CodePKEParams(
        n=32,
        k=16,
        secret_weight=3,
        encryption_error_weight=1,
        repetitions=48,
        zero_threshold=0.25,
    )
    pk, sk = keygen(params, rng=random.Random(80_001))

    p0 = recover_sparse_error_lee_brickell(
        pk,
        p=0,
        rng=random.Random(80_002),
        max_information_sets=2048,
    )
    p1 = recover_sparse_error_lee_brickell(
        pk,
        p=1,
        rng=random.Random(80_003),
        max_information_sets=512,
    )
    model = best_lee_brickell_cost(256, 128, 30, max_p=4)

    p0_key = CodePKESecretKey(p0.witness, params)
    p1_key = CodePKESecretKey(p1.witness, params)
    p0_valid = public_secret_orthogonality_holds(pk, p0_key)
    p1_valid = public_secret_orthogonality_holds(pk, p1_key)
    p0_exact = p0.witness == sk.error
    p1_exact = p1.witness == sk.error

    print("attack=Lee-Brickell generalized information-set decoding")
    print(f"toy-p0-valid-public-witness={p0_valid}")
    print(f"toy-p0-original-witness={p0_exact}")
    print(f"toy-p0-information-sets={p0.information_sets_sampled}")
    print(f"toy-p0-invertible-sets={p0.invertible_information_sets}")
    print(f"toy-p0-guesses={p0.guesses_tested}")
    print(f"toy-p1-valid-public-witness={p1_valid}")
    print(f"toy-p1-original-witness={p1_exact}")
    print(f"toy-p1-information-sets={p1.information_sets_sampled}")
    print(f"toy-p1-invertible-sets={p1.invertible_information_sets}")
    print(f"toy-p1-guesses={p1.guesses_tested}")
    print("model-profile=n256-k128-w30")
    print(f"model-best-p={model.p}")
    print(f"model-expected-information-set-bits={model.expected_information_set_bits:.6f}")
    print(f"model-estimated-naive-op-bits={model.estimated_total_ops_bits:.6f}")
    print(f"model-guesses-per-invertible-set={model.guesses_per_invertible_set}")
    print("interpretation=valid public witness is attack objective; identity with keygen witness is unnecessary")
    return 0 if p0_valid and p1_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
