#!/usr/bin/env python3
"""Exercise Dumer recovery and compare current ISD reference models."""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_dumer import best_dumer_cost, recover_sparse_error_dumer
from code_isd import best_lee_brickell_cost
from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)
from code_stern import best_stern_cost


def main() -> int:
    toy = CodePKEParams(
        n=32,
        k=16,
        secret_weight=4,
        encryption_error_weight=1,
        repetitions=48,
        zero_threshold=0.25,
    )
    pk, original = keygen(toy, rng=random.Random(91))
    recovered = recover_sparse_error_dumer(
        pk,
        p=2,
        l=4,
        rng=random.Random(92),
        max_information_sets=2048,
    )
    candidate = CodePKESecretKey(recovered.witness, toy)
    valid = public_secret_orthogonality_holds(pk, candidate)
    exact = recovered.witness == original.error

    lee = best_lee_brickell_cost(256, 128, 48, max_p=4)
    stern = best_stern_cost(256, 128, 48, max_p=4, max_l=32)
    dumer = best_dumer_cost(256, 128, 48, max_p=8, max_l=32)

    print("attack=Dumer-style enlarged-information-set collision decoding")
    print(f"toy-valid-public-witness={valid}")
    print(f"toy-original-witness={exact}")
    print(f"toy-information-sets={recovered.information_sets_sampled}")
    print(f"toy-systematic-sets={recovered.systematic_information_sets}")
    print(f"toy-left-list-entries={recovered.left_list_entries}")
    print(f"toy-right-list-entries={recovered.right_list_entries}")
    print(f"toy-collision-candidates={recovered.collision_candidates_tested}")
    print("model-profile=n256-k128-w48")
    print(f"lee-modeled-op-bits={lee.estimated_total_ops_bits:.6f}")
    print(f"stern-modeled-op-bits={stern.estimated_total_ops_bits:.6f}")
    print(f"dumer-best-p={dumer.p}")
    print(f"dumer-best-l={dumer.l}")
    print(f"dumer-modeled-op-bits={dumer.estimated_total_ops_bits:.6f}")
    print(f"dumer-memory-entry-bits={dumer.estimated_memory_bits:.6f}")
    print(f"dumer-vs-stern-op-bit-reduction={stern.estimated_total_ops_bits - dumer.estimated_total_ops_bits:.6f}")
    print("interpretation=executable Dumer mechanism + transparent reference model; not security bits")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
