import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams
from code_profile_audit import (
    audit_code_profile,
    fixed_weight_intersection_odd_probability,
    minimum_weight_for_trivial_floor,
    sparse_witness_enumeration_bits,
)


TOY = CodePKEParams(
    n=64,
    k=32,
    secret_weight=2,
    encryption_error_weight=2,
    repetitions=96,
    zero_threshold=0.25,
)


class CodeProfileAuditTests(unittest.TestCase):
    def test_toy_witness_space_matches_exact_combinatorics(self):
        audit = audit_code_profile(TOY)
        self.assertEqual(audit.witness_space_size, math.comb(64, 2))
        self.assertAlmostEqual(audit.trivial_enumeration_bits, math.log2(2016))
        self.assertFalse(audit.meets_trivial_enumeration_floor(16))
        self.assertTrue(audit.meets_trivial_enumeration_floor(10))

    def test_fixed_weight_odd_intersection_probability(self):
        # For w=t=2, odd intersection means exactly one common coordinate.
        expected = (math.comb(2, 1) * math.comb(62, 1)) / math.comb(64, 2)
        self.assertAlmostEqual(
            fixed_weight_intersection_odd_probability(64, 2, 2),
            expected,
        )

    def test_audit_predicts_large_correctness_gap(self):
        audit = audit_code_profile(TOY)
        self.assertAlmostEqual(audit.zero_inner_product_one_probability, 124 / 2016)
        self.assertEqual(audit.decision_cutoff_ones, 24)
        self.assertLess(audit.bit0_failure_probability, 1e-8)
        self.assertLess(audit.bit1_failure_probability, 2e-7)
        self.assertLess(audit.worst_bit_failure_probability, 2e-7)

    def test_minimum_weight_floor_is_only_trivial_search_guard(self):
        weight = minimum_weight_for_trivial_floor(256, 128)
        self.assertIsNotNone(weight)
        assert weight is not None
        self.assertGreaterEqual(sparse_witness_enumeration_bits(256, weight), 128)
        if weight > 0:
            self.assertLess(sparse_witness_enumeration_bits(256, weight - 1), 128)

    def test_invalid_policy_values_rejected(self):
        audit = audit_code_profile(TOY)
        with self.assertRaises(ValueError):
            audit.meets_trivial_enumeration_floor(-1)
        with self.assertRaises(ValueError):
            audit.meets_failure_ceiling(1.1)


if __name__ == "__main__":
    unittest.main()
