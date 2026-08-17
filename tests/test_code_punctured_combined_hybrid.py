import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_punctured_combined_hybrid import (
    assess_combined_hybrid,
    assess_punctured_hybrid,
    log2_binomial,
    optimize_punctured_weight,
)


class PuncturedCombinedHybridTests(unittest.TestCase):
    def test_log2_binomial_exact_small_values(self):
        self.assertEqual(log2_binomial(5, 0), 0.0)
        self.assertEqual(log2_binomial(5, 5), 0.0)
        self.assertAlmostEqual(log2_binomial(5, 2), math.log2(10.0))
        self.assertAlmostEqual(log2_binomial(10, 3), math.log2(120.0))

    def test_punctured_twenty_percent_reference_point(self):
        report = assess_punctured_hybrid(1694, 847, 230, 678, 204)
        self.assertTrue(report.is_punctured_hybrid)
        self.assertEqual(report.reduced_length, 1016)
        self.assertEqual(report.reduced_dimension, 847)
        self.assertEqual(report.reduced_parity_checks, 169)
        self.assertEqual(report.reduced_weight, 26)
        self.assertEqual(report.matrix_representation_qubits, 143_143)
        self.assertAlmostEqual(report.matrix_memory_fraction, 169 / 847, places=15)
        self.assertEqual(report.log2_correct_zero_guess_probability, 0.0)
        self.assertAlmostEqual(report.log2_expected_outer_iterations, 201.42165773146678, places=10)
        self.assertAlmostEqual(report.log2_expected_reduced_solutions, 1.858446431300763, places=10)
        self.assertAlmostEqual(report.log2_repeat_factor, 1.858446431300763, places=10)
        self.assertAlmostEqual(report.log2_quantum_subroutine_proxy, 33.94231305537318, places=10)
        self.assertAlmostEqual(report.proof_time_proxy_bits, 237.22241721814072, places=10)

    def test_combined_twenty_percent_reference_point(self):
        report = assess_combined_hybrid(1694, 847, 230, 582, 306, 86)
        self.assertFalse(report.is_punctured_hybrid)
        self.assertEqual(report.reduced_length, 806)
        self.assertEqual(report.reduced_dimension, 265)
        self.assertEqual(report.reduced_parity_checks, 541)
        self.assertEqual(report.reduced_weight, 144)
        self.assertEqual(report.matrix_representation_qubits, 143_365)
        self.assertAlmostEqual(report.matrix_memory_fraction, 0.19983719189472116, places=15)
        self.assertAlmostEqual(report.log2_correct_zero_guess_probability, -152.95258266467033, places=10)
        self.assertAlmostEqual(report.log2_expected_outer_iterations, 13.766808528874662, places=10)
        self.assertAlmostEqual(report.log2_expected_reduced_solutions, 0.0027718871389197375, places=10)
        self.assertAlmostEqual(report.log2_quantum_subroutine_proxy, 46.727703346478535, places=10)
        self.assertAlmostEqual(report.proof_time_proxy_bits, 213.44986642716245, places=10)

    def test_combined_has_lower_proxy_than_punctured_at_comparable_matrix_memory(self):
        punctured = assess_punctured_hybrid(1694, 847, 230, 678, 204)
        combined = assess_combined_hybrid(1694, 847, 230, 582, 306, 86)
        self.assertLess(abs(punctured.matrix_memory_fraction - combined.matrix_memory_fraction), 0.001)
        self.assertLess(combined.proof_time_proxy_bits, punctured.proof_time_proxy_bits)

    def test_fixed_ab_optimizer_reproduces_reference_p(self):
        punctured = optimize_punctured_weight(1694, 847, 230, 0, 678)
        combined = optimize_punctured_weight(1694, 847, 230, 582, 306)
        self.assertEqual(punctured.punctured_weight, 204)
        self.assertAlmostEqual(punctured.proof_time_proxy_bits, 237.22241721814072, places=10)
        self.assertEqual(combined.punctured_weight, 86)
        self.assertAlmostEqual(combined.proof_time_proxy_bits, 213.44986642716245, places=10)

    def test_ten_and_one_percent_combined_reference_points(self):
        tenth = assess_combined_hybrid(1694, 847, 230, 658, 468, 129)
        one_percent = assess_combined_hybrid(1694, 847, 230, 780, 740, 202)
        self.assertAlmostEqual(tenth.matrix_memory_fraction, 0.0998468098392967, places=15)
        self.assertAlmostEqual(tenth.proof_time_proxy_bits, 226.90443233590446, places=10)
        self.assertAlmostEqual(one_percent.matrix_memory_fraction, 0.009992905023494269, places=15)
        self.assertAlmostEqual(one_percent.proof_time_proxy_bits, 248.62272115077332, places=10)

    def test_validation(self):
        with self.assertRaises(ValueError):
            assess_combined_hybrid(64, 64, 4, 0, 0, 0)
        with self.assertRaises(ValueError):
            assess_combined_hybrid(64, 32, 33, 0, 0, 0)
        with self.assertRaises(ValueError):
            assess_combined_hybrid(64, 32, 4, 32, 0, 0)
        with self.assertRaises(ValueError):
            assess_combined_hybrid(64, 32, 4, 0, 32, 0)
        with self.assertRaises(ValueError):
            assess_combined_hybrid(64, 32, 4, 0, 2, 3)
        with self.assertRaises(TypeError):
            assess_combined_hybrid(64.0, 32, 4, 0, 0, 0)
        with self.assertRaises(ValueError):
            log2_binomial(5, 6)


if __name__ == "__main__":
    unittest.main()
