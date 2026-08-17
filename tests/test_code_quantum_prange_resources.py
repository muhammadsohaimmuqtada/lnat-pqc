import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_quantum_prange_resources import (
    PAPER_ARXIV,
    PAPER_EPRINT,
    QISD_REFERENCE_COMMIT,
    QISD_REPOSITORY,
    assess_quantum_prange_resources,
    depth_optimized_qubits,
    idealized_grover_iteration_bits,
    width_optimized_depth_scale_bits,
    width_optimized_qubits,
)


class QuantumPrangeResourceTests(unittest.TestCase):
    def test_reference_provenance_is_pinned(self):
        self.assertEqual(PAPER_EPRINT, "2021/1608")
        self.assertEqual(PAPER_ARXIV, "2112.06157")
        self.assertEqual(QISD_REPOSITORY, "qiboteam/qISD")
        self.assertEqual(
            QISD_REFERENCE_COMMIT,
            "456b3c60987e426a18d4ed4e5ebeaee3d2570958",
        )

    def test_table2_width_formulas(self):
        self.assertEqual(width_optimized_qubits(1694, 847), 721_643)
        self.assertEqual(depth_optimized_qubits(1694, 847), 1_438_205)

    def test_current_combined_frontier_resource_surface(self):
        estimate = assess_quantum_prange_resources(1694, 847, 230)
        self.assertAlmostEqual(estimate.classical_expected_trial_bits, 256.050133924160, places=9)
        self.assertAlmostEqual(estimate.prange_success_log2, -256.050133924160, places=9)
        self.assertAlmostEqual(estimate.grover_iteration_bits, 127.676563091552, places=9)
        self.assertEqual(estimate.width_optimized_qubits, 721_643)
        self.assertEqual(estimate.depth_optimized_qubits, 1_438_205)
        self.assertAlmostEqual(estimate.width_optimized_depth_scale_bits, 163.626791036547, places=9)
        self.assertEqual(estimate.reference_repository, "qiboteam/qISD")
        self.assertEqual(
            estimate.reference_commit,
            "456b3c60987e426a18d4ed4e5ebeaee3d2570958",
        )

    def test_grover_constant_is_explicit(self):
        self.assertAlmostEqual(
            idealized_grover_iteration_bits(128.0),
            64.0 + math.log2(math.pi / 4.0),
        )

    def test_depth_scale_keeps_table2_expression_literal(self):
        b = 128.0
        expected = (
            0.5 * b
            + 3.0 * math.log2(256)
            + math.log2(math.log2(256))
        )
        self.assertAlmostEqual(width_optimized_depth_scale_bits(256, b), expected)
        self.assertNotAlmostEqual(
            width_optimized_depth_scale_bits(256, b),
            idealized_grover_iteration_bits(b)
            + 3.0 * math.log2(256)
            + math.log2(math.log2(256)),
        )

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            assess_quantum_prange_resources(64, 64, 4)
        with self.assertRaises(ValueError):
            assess_quantum_prange_resources(64, 32, 33)
        with self.assertRaises(TypeError):
            width_optimized_qubits(64.0, 32)
        with self.assertRaises(ValueError):
            depth_optimized_qubits(64, 64)
        with self.assertRaises(TypeError):
            idealized_grover_iteration_bits(True)
        with self.assertRaises(ValueError):
            idealized_grover_iteration_bits(-1.0)


if __name__ == "__main__":
    unittest.main()
