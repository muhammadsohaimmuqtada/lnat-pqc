import math
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)
from code_stern import (
    best_stern_cost,
    recover_sparse_error_stern,
    stern_cost_point,
    stern_success_probability,
)


class SternISDTests(unittest.TestCase):
    def test_success_probability_matches_combinatorial_event(self):
        n, k, w, p, l = 32, 16, 4, 1, 4
        expected = (
            math.comb(8, 1)
            * math.comb(8, 1)
            * math.comb(12, 2)
            / math.comb(32, 4)
        )
        self.assertAlmostEqual(stern_success_probability(n, k, w, p, l), expected)

    def test_recovery_finds_valid_toy_witness(self):
        params = CodePKEParams(
            n=32,
            k=16,
            secret_weight=4,
            encryption_error_weight=1,
            repetitions=48,
            zero_threshold=0.25,
        )
        pk, _ = keygen(params, rng=random.Random(10))
        result = recover_sparse_error_stern(
            pk,
            p=1,
            l=4,
            rng=random.Random(2),
            max_information_sets=512,
        )
        candidate = CodePKESecretKey(result.witness, params)
        self.assertTrue(public_secret_orthogonality_holds(pk, candidate))
        self.assertEqual(result.witness.bit_count(), params.secret_weight)
        self.assertGreater(result.left_list_entries, 0)
        self.assertGreater(result.right_list_entries, 0)
        self.assertGreater(result.collision_candidates_tested, 0)

    def test_cost_point_reports_time_and_memory(self):
        point = stern_cost_point(256, 128, 30, 2, 8)
        self.assertGreater(point.estimated_total_ops, 0)
        self.assertGreater(point.estimated_memory_entries, 0)
        self.assertGreater(point.expected_collisions_per_invertible_set, 0)
        self.assertAlmostEqual(
            point.estimated_memory_bits,
            math.log2(math.comb(64, 2)),
        )

    def test_best_stern_model_beats_naive_p1_setting_for_screened_profile(self):
        best = best_stern_cost(256, 128, 30, max_p=4, max_l=24)
        baseline = stern_cost_point(256, 128, 30, 1, 1)
        self.assertLessEqual(best.estimated_total_ops, baseline.estimated_total_ops)
        self.assertIn(best.p, range(1, 5))
        self.assertIn(best.l, range(1, 25))

    def test_invalid_collision_parameters_rejected(self):
        with self.assertRaises(ValueError):
            stern_success_probability(32, 16, 4, 0, 4)
        with self.assertRaises(ValueError):
            stern_success_probability(32, 16, 4, 1, 17)


if __name__ == "__main__":
    unittest.main()
