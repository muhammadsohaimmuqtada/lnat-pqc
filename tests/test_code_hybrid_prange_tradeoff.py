import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_hybrid_prange_tradeoff import (
    assess_hybrid_prange_tradeoff,
    binary_entropy,
    hybrid_prange_time_exponent,
)


class HybridPrangeTradeoffTests(unittest.TestCase):
    def test_theorem_endpoints(self):
        R = 0.5
        tau = 230 / 1694
        self.assertEqual(hybrid_prange_time_exponent(R, tau, 1.0), 0.5)
        self.assertEqual(hybrid_prange_time_exponent(R, tau, 0.0), 1.0)

    def test_current_point_full_quantum_matrix_memory(self):
        report = assess_hybrid_prange_tradeoff(1694, 847, 230, 0)
        self.assertEqual(report.retained_quantum_dimension, 847)
        self.assertEqual(report.reduced_n, 1694)
        self.assertEqual(report.reduced_k, 847)
        self.assertEqual(report.matrix_representation_qubits, 717_409)
        self.assertEqual(report.full_matrix_representation_qubits, 717_409)
        self.assertEqual(report.matrix_memory_fraction, 1.0)
        self.assertEqual(report.time_exponent, 0.5)

    def test_integer_twenty_percent_memory_example(self):
        # Guess 678 zero coordinates classically, leaving 169 of the original
        # 847 quantum information coordinates.  This is ~19.95% of the full
        # matrix-representation footprint, with no fractional coordinates.
        report = assess_hybrid_prange_tradeoff(1694, 847, 230, 678)
        self.assertEqual(report.retained_quantum_dimension, 169)
        self.assertEqual(report.reduced_n, 1016)
        self.assertEqual(report.reduced_k, 169)
        self.assertEqual(report.reduced_weight, 230)
        self.assertAlmostEqual(report.qubit_fraction_delta, 169 / 847, places=15)
        self.assertEqual(report.matrix_representation_qubits, 143_143)
        self.assertAlmostEqual(report.matrix_memory_fraction, 169 / 847, places=15)
        self.assertAlmostEqual(report.time_exponent, 0.864550685541684, places=12)

    def test_ten_percent_memory_example(self):
        report = assess_hybrid_prange_tradeoff(1694, 847, 230, 762)
        self.assertEqual(report.retained_quantum_dimension, 85)
        self.assertEqual(report.matrix_representation_qubits, 71_995)
        self.assertAlmostEqual(report.time_exponent, 0.928317769736266, places=12)

    def test_less_quantum_memory_increases_time_exponent(self):
        full = assess_hybrid_prange_tradeoff(1694, 847, 230, 0)
        half = assess_hybrid_prange_tradeoff(1694, 847, 230, 423)
        fifth = assess_hybrid_prange_tradeoff(1694, 847, 230, 678)
        tenth = assess_hybrid_prange_tradeoff(1694, 847, 230, 762)
        classical = assess_hybrid_prange_tradeoff(1694, 847, 230, 847)
        exponents = [full.time_exponent, half.time_exponent, fifth.time_exponent, tenth.time_exponent, classical.time_exponent]
        self.assertEqual(exponents, sorted(exponents))
        self.assertEqual(classical.matrix_representation_qubits, 0)
        self.assertEqual(classical.time_exponent, 1.0)

    def test_entropy_boundaries(self):
        self.assertEqual(binary_entropy(0.0), 0.0)
        self.assertEqual(binary_entropy(1.0), 0.0)
        self.assertAlmostEqual(binary_entropy(0.5), 1.0)

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            hybrid_prange_time_exponent(0.5, 0.6, 1.0)
        with self.assertRaises(ValueError):
            hybrid_prange_time_exponent(0.5, 0.1, 1.1)
        with self.assertRaises(ValueError):
            assess_hybrid_prange_tradeoff(64, 32, 33, 0)
        with self.assertRaises(ValueError):
            assess_hybrid_prange_tradeoff(64, 32, 4, 33)
        with self.assertRaises(TypeError):
            assess_hybrid_prange_tradeoff(64.0, 32, 4, 0)


if __name__ == "__main__":
    unittest.main()
