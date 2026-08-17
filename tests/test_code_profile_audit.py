import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams
from code_profile_audit import (
    audit_code_profile,
    fixed_weight_intersection_odd_probability,
    kem_failure_union_bound,
    kem_seed_failure_probability,
    minimum_repetitions_for_failure,
    minimum_repetitions_for_kem_failure,
    minimum_weight_for_prange_trial_floor,
    minimum_weight_for_trivial_floor,
    optimal_decision_for_repetitions,
    screen_necessary_candidate,
    screen_necessary_kem_candidate,
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

    def test_prange_model_exposes_stronger_public_attack(self):
        audit = audit_code_profile(TOY)
        expected = math.comb(64, 2) / math.comb(32, 2)
        self.assertAlmostEqual(audit.prange_expected_information_sets, expected)
        self.assertAlmostEqual(audit.prange_expected_trial_bits, math.log2(expected))
        self.assertLess(audit.prange_expected_trial_bits, 3.0)
        self.assertFalse(audit.meets_prange_trial_floor(8))
        self.assertTrue(audit.meets_prange_trial_floor(2))

    def test_fixed_weight_odd_intersection_probability(self):
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

    def test_kem_failure_composition_exposes_bit_vs_seed_gap(self):
        p0 = 8.11524514255e-10
        p1 = 9.14727218523e-10
        modeled = kem_seed_failure_probability(p0, p1, 128)
        bound = kem_failure_union_bound(p0, p1, 128)
        self.assertGreater(modeled, 1e-7)
        self.assertLess(modeled, 1.2e-7)
        self.assertGreater(bound, modeled)
        self.assertGreater(bound, 1e-7)
        self.assertLess(bound, 1.3e-7)

    def test_minimum_weight_floor_is_only_trivial_search_guard(self):
        weight = minimum_weight_for_trivial_floor(256, 128)
        self.assertIsNotNone(weight)
        assert weight is not None
        self.assertGreaterEqual(sparse_witness_enumeration_bits(256, weight), 128)
        if weight > 0:
            self.assertLess(sparse_witness_enumeration_bits(256, weight - 1), 128)

    def test_minimum_weight_for_prange_trial_floor(self):
        self.assertEqual(minimum_weight_for_prange_trial_floor(256, 128, 32), 30)
        self.assertLess(
            audit_code_profile(
                CodePKEParams(
                    n=256,
                    k=128,
                    secret_weight=29,
                    encryption_error_weight=1,
                    repetitions=1,
                    zero_threshold=0.25,
                )
            ).prange_expected_trial_bits,
            32,
        )

    def test_optimal_decision_rule_for_legacy_bit_frontier(self):
        p_zero = fixed_weight_intersection_odd_probability(256, 30, 1)
        self.assertEqual(p_zero, 30 / 256)
        decision = optimal_decision_for_repetitions(p_zero, 183)
        self.assertEqual(decision.cutoff_ones, 52)
        self.assertAlmostEqual(decision.threshold, 52 / 183)
        self.assertLess(decision.worst_failure_probability, 1e-9)

    def test_legacy_minimum_repetitions_for_per_bit_failure(self):
        decision = minimum_repetitions_for_failure(
            30 / 256,
            1e-9,
            max_repetitions=256,
        )
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(decision.repetitions, 183)
        self.assertEqual(decision.cutoff_ones, 52)

    def test_minimum_repetitions_for_full_kem_failure(self):
        audit = minimum_repetitions_for_kem_failure(
            30 / 256,
            encapsulated_bits=128,
            failure_ceiling=1e-9,
            max_repetitions=300,
        )
        self.assertIsNotNone(audit)
        assert audit is not None
        self.assertEqual(audit.decision.repetitions, 233)
        self.assertEqual(audit.decision.cutoff_ones, 66)
        self.assertLessEqual(audit.conservative_union_bound, 1e-9)
        self.assertLessEqual(audit.modeled_seed_failure_probability, 1e-9)

    def test_legacy_screen_known_point_retained(self):
        candidate = screen_necessary_candidate(
            n=256,
            k=128,
            prange_trial_floor_bits=32,
            encryption_error_weight=1,
            failure_ceiling=1e-9,
            max_repetitions=256,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.secret_weight, 30)
        self.assertEqual(candidate.repetitions, 183)
        self.assertEqual(candidate.cutoff_ones, 52)

    def test_full_kem_screen_known_point(self):
        candidate = screen_necessary_kem_candidate(
            n=256,
            k=128,
            prange_trial_floor_bits=32,
            encryption_error_weight=1,
            encapsulated_bits=128,
            kem_failure_ceiling=1e-9,
            max_repetitions=300,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.secret_weight, 30)
        self.assertGreaterEqual(candidate.prange_expected_trial_bits, 32)
        self.assertEqual(candidate.encapsulated_bits, 128)
        self.assertEqual(candidate.repetitions, 233)
        self.assertEqual(candidate.cutoff_ones, 66)
        self.assertLessEqual(candidate.conservative_kem_failure_bound, 1e-9)
        self.assertLessEqual(candidate.modeled_seed_failure_probability, 1e-9)
        self.assertGreater(candidate.full_witness_enumeration_bits, 32)

    def test_invalid_policy_values_rejected(self):
        audit = audit_code_profile(TOY)
        with self.assertRaises(ValueError):
            audit.meets_trivial_enumeration_floor(-1)
        with self.assertRaises(ValueError):
            audit.meets_prange_trial_floor(-1)
        with self.assertRaises(ValueError):
            audit.meets_failure_ceiling(1.1)
        with self.assertRaises(ValueError):
            minimum_repetitions_for_failure(0.1, 0.0)
        with self.assertRaises(ValueError):
            minimum_repetitions_for_kem_failure(0.1, 0, 1e-9)
        with self.assertRaises(ValueError):
            kem_seed_failure_probability(0.1, 0.1, 0)
        with self.assertRaises(ValueError):
            screen_necessary_kem_candidate(
                n=64,
                k=64,
                prange_trial_floor_bits=8,
                encryption_error_weight=1,
                encapsulated_bits=128,
                kem_failure_ceiling=1e-6,
            )


if __name__ == "__main__":
    unittest.main()
