import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_quantum_isd import assess_quantum_isd, groverized_iteration_bits


class QuantumISDScreenTests(unittest.TestCase):
    def test_grover_halves_search_exponent(self):
        self.assertEqual(groverized_iteration_bits(128.0), 64.0)
        self.assertEqual(groverized_iteration_bits(0.0), 0.0)
        self.assertTrue(math.isinf(groverized_iteration_bits(math.inf)))

    def test_current_classical_frontier_fails_128_quantum_iteration_screen(self):
        report = assess_quantum_isd(1064, 532, 117)
        self.assertEqual(report.effective_quantum_search_attack, "GroverizedPrange")
        self.assertAlmostEqual(report.classical_prange_trial_bits, 127.3587794323, places=9)
        self.assertAlmostEqual(report.grover_prange_iteration_bits, 63.6793897162, places=9)
        self.assertAlmostEqual(
            report.classical_support_enumeration_bits,
            527.1119753008,
            places=9,
        )
        self.assertAlmostEqual(report.grover_support_iteration_bits, 263.5559876504, places=9)
        self.assertFalse(report.passes_iteration_floor(128.0))
        self.assertFalse(report.passes_iteration_floor(64.0))
        self.assertTrue(report.passes_iteration_floor(63.0))

    def test_direct_support_search_is_also_grover_screened(self):
        report = assess_quantum_isd(256, 128, 28)
        self.assertAlmostEqual(report.grover_prange_iteration_bits, 15.1961920757, places=9)
        self.assertAlmostEqual(report.grover_support_iteration_bits, 61.9224585969, places=9)
        self.assertEqual(report.effective_quantum_search_attack, "GroverizedPrange")

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            assess_quantum_isd(64, 64, 4)
        with self.assertRaises(ValueError):
            assess_quantum_isd(64, 32, 65)
        with self.assertRaises(TypeError):
            assess_quantum_isd(64.0, 32, 4)
        with self.assertRaises(ValueError):
            groverized_iteration_bits(-1.0)
        with self.assertRaises(TypeError):
            groverized_iteration_bits(True)


if __name__ == "__main__":
    unittest.main()
