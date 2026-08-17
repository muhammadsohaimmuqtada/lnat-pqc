import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_attack_frontier import (
    minimum_weight_for_dumer_operation_floor,
    minimum_weight_for_stern_operation_floor,
    screen_attack_aware_kem_candidate,
)


class AttackAwareFrontierTests(unittest.TestCase):
    def test_stern_floor_moves_screened_weight_above_old_prange_point(self):
        result = minimum_weight_for_stern_operation_floor(256, 128, 64.0, max_p=4, max_l=32)
        self.assertIsNotNone(result)
        assert result is not None
        weight, point = result
        self.assertEqual(weight, 48)
        self.assertEqual(point.p, 3)
        self.assertEqual(point.l, 12)
        self.assertGreaterEqual(point.estimated_total_ops_bits, 64.0)

    def test_dumer_floor_moves_weight_above_stern48_point(self):
        result = minimum_weight_for_dumer_operation_floor(256, 128, 64.0, max_p=8, max_l=32)
        self.assertIsNotNone(result)
        assert result is not None
        weight, point = result
        self.assertEqual(weight, 49)
        self.assertEqual(point.p, 6)
        self.assertEqual(point.l, 12)
        self.assertGreaterEqual(point.estimated_total_ops_bits, 64.0)

    def test_stern_only_regression_remains_reproducible(self):
        candidate = screen_attack_aware_kem_candidate(
            n=256,
            k=128,
            prange_trial_floor_bits=32.0,
            stern_operation_floor_bits=64.0,
            dumer_operation_floor_bits=0.0,
            encryption_error_weight=1,
            encapsulated_bits=128,
            kem_failure_ceiling=1e-9,
            max_repetitions=450,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.secret_weight, 48)
        self.assertEqual(candidate.repetitions, 394)
        self.assertEqual(candidate.cutoff_ones, 131)
        self.assertLess(candidate.dumer_modeled_ops_bits, 64.0)

    def test_dumer_aware_full_kem_screen_known_point(self):
        candidate = screen_attack_aware_kem_candidate(
            n=256,
            k=128,
            prange_trial_floor_bits=32.0,
            stern_operation_floor_bits=64.0,
            dumer_operation_floor_bits=64.0,
            encryption_error_weight=1,
            encapsulated_bits=128,
            kem_failure_ceiling=1e-9,
            max_repetitions=450,
            stern_max_p=4,
            stern_max_l=32,
            dumer_max_p=8,
            dumer_max_l=32,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.secret_weight, 49)
        self.assertGreaterEqual(candidate.prange_expected_trial_bits, 32.0)
        self.assertGreaterEqual(candidate.stern_modeled_ops_bits, 64.0)
        self.assertGreaterEqual(candidate.dumer_modeled_ops_bits, 64.0)
        self.assertEqual(candidate.dumer_p, 6)
        self.assertEqual(candidate.dumer_l, 12)
        self.assertEqual(candidate.repetitions, 406)
        self.assertEqual(candidate.cutoff_ones, 136)
        self.assertLessEqual(candidate.conservative_kem_failure_bound, 1e-9)
        self.assertLessEqual(candidate.modeled_seed_failure_probability, 1e-9)

    def test_weight48_does_not_pass_dumer64(self):
        candidate = screen_attack_aware_kem_candidate(
            n=256,
            k=128,
            prange_trial_floor_bits=32.0,
            stern_operation_floor_bits=64.0,
            dumer_operation_floor_bits=64.0,
            encryption_error_weight=1,
            encapsulated_bits=128,
            kem_failure_ceiling=1e-9,
            max_repetitions=400,
        )
        self.assertIsNone(candidate)

    def test_invalid_policy_values_rejected(self):
        with self.assertRaises(ValueError):
            minimum_weight_for_stern_operation_floor(64, 32, -1)
        with self.assertRaises(ValueError):
            minimum_weight_for_dumer_operation_floor(64, 32, -1)
        with self.assertRaises(ValueError):
            screen_attack_aware_kem_candidate(
                n=64,
                k=64,
                prange_trial_floor_bits=8,
                stern_operation_floor_bits=8,
                dumer_operation_floor_bits=8,
                encryption_error_weight=1,
                encapsulated_bits=128,
                kem_failure_ceiling=1e-6,
            )
        with self.assertRaises(ValueError):
            screen_attack_aware_kem_candidate(
                n=64,
                k=32,
                prange_trial_floor_bits=8,
                stern_operation_floor_bits=8,
                dumer_operation_floor_bits=-1,
                encryption_error_weight=1,
                encapsulated_bits=128,
                kem_failure_ceiling=1e-6,
            )


if __name__ == "__main__":
    unittest.main()
