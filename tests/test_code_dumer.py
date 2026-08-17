import math
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_dumer import (
    best_dumer_cost,
    dumer_cost_point,
    dumer_success_probability,
    recover_sparse_error_dumer,
)
from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)
from code_stern import best_stern_cost


class DumerISDTests(unittest.TestCase):
    def test_success_probability_matches_exact_split_event(self):
        n, k, w, p, l = 32, 16, 4, 2, 4
        expected = (
            math.comb(10, 1)
            * math.comb(10, 1)
            * math.comb(12, 2)
            / math.comb(32, 4)
        )
        self.assertAlmostEqual(dumer_success_probability(n, k, w, p, l), expected)

    def test_recovery_finds_valid_public_witness(self):
        params = CodePKEParams(
            n=32,
            k=16,
            secret_weight=4,
            encryption_error_weight=1,
            repetitions=48,
            zero_threshold=0.25,
        )
        pk, _ = keygen(params, rng=random.Random(91))
        result = recover_sparse_error_dumer(
            pk,
            p=2,
            l=4,
            rng=random.Random(92),
            max_information_sets=2048,
        )
        candidate = CodePKESecretKey(result.witness, params)
        self.assertTrue(public_secret_orthogonality_holds(pk, candidate))
        self.assertEqual(result.witness.bit_count(), params.secret_weight)
        self.assertGreater(result.systematic_information_sets, 0)
        self.assertGreater(result.left_list_entries, 0)
        self.assertGreater(result.right_list_entries, 0)
        self.assertGreater(result.collision_candidates_tested, 0)

    def test_cost_point_reports_list_and_memory_work(self):
        point = dumer_cost_point(256, 128, 48, 6, 12)
        self.assertGreater(point.estimated_total_ops, 0)
        self.assertGreater(point.estimated_memory_entries, 0)
        self.assertGreater(point.expected_collisions_per_systematic_set, 0)
        self.assertEqual(point.left_list_size, math.comb(70, 3))

    def test_dumer_model_improves_current_stern48_reference(self):
        stern = best_stern_cost(256, 128, 48, max_p=4, max_l=32)
        dumer = best_dumer_cost(256, 128, 48, max_p=8, max_l=32)
        self.assertLess(dumer.estimated_total_ops_bits, stern.estimated_total_ops_bits)
        self.assertEqual(dumer.p, 6)
        self.assertEqual(dumer.l, 12)

    def test_invalid_parameters_rejected(self):
        with self.assertRaises(ValueError):
            dumer_success_probability(32, 16, 4, 1, 4)
        with self.assertRaises(ValueError):
            dumer_success_probability(32, 16, 4, 2, 16)
        with self.assertRaises(ValueError):
            best_dumer_cost(32, 16, 4, max_p=1)


if __name__ == "__main__":
    unittest.main()
