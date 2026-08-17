#!/usr/bin/env python3
"""Run reduced Stern recovery and compare the transparent larger-profile models."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_isd import best_lee_brickell_cost
from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)
from code_stern import best_stern_cost, recover_sparse_error_stern


def main() -> int:
    toy = CodePKEParams(
        n=32,
        k=16,
        secret_weight=4,
        encryption_error_weight=1,
        repetitions=48,
        zero_threshold=0.25,
    )
    pk, original_sk = keygen(toy, rng=random.Random(10))
    recovered = recover_sparse_error_stern(
        pk,
        p=1,
        l=4,
        rng=random.Random(2),
        max_information_sets=512,
    )

    candidate_sk = CodePKESecretKey(recovered.witness, toy)
    valid = public_secret_orthogonality_holds(pk, candidate_sk)
    exact = recovered.witness == original_sk.error
    lee = best_lee_brickell_cost(256, 128, 30, max_p=4)
    stern = best_stern_cost(256, 128, 30, max_p=4, max_l=24)

    print("attack=Stern-style collision information-set decoding")
    print(f"toy-valid-public-witness={valid}")
    print(f"toy-original-witness={exact}")
    print(f"toy-information-sets={recovered.information_sets_sampled}")
    print(f"toy-invertible-sets={recovered.invertible_information_sets}")
    print(f"toy-left-list-entries={recovered.left_list_entries}")
    print(f"toy-right-list-entries={recovered.right_list_entries}")
    print(f"toy-collision-candidates={recovered.collision_candidates_tested}")
    print("model-profile=n256-k128-w30")
    print(f"lee-best-p={lee.p}")
    print(f"lee-naive-op-bits={lee.estimated_total_ops_bits:.6f}")
    print(f"stern-best-p={stern.p}")
    print(f"stern-best-l={stern.l}")
    print(f"stern-estimated-op-bits={stern.estimated_total_ops_bits:.6f}")
    print(f"stern-memory-entry-bits={stern.estimated_memory_bits:.6f}")
    print(f"modeled-op-bit-reduction={lee.estimated_total_ops_bits - stern.estimated_total_ops_bits:.6f}")
    print("interpretation=valid public witness is attack objective; model remains screening-only")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
