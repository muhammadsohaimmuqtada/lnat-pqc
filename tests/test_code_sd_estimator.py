import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_sd_estimator import (
    EXPECTED_UPSTREAM_VERSION,
    estimate_upstream_isd,
    upstream_available,
)


class UpstreamEstimatorBridgeTests(unittest.TestCase):
    def test_rejects_invalid_instances_without_optional_dependency(self):
        with self.assertRaises(ValueError):
            estimate_upstream_isd(10, 10, 2)
        with self.assertRaises(ValueError):
            estimate_upstream_isd(10, 5, 11)

    @unittest.skipUnless(upstream_available(), "optional estimator dependency not installed")
    def test_modern_isd_crosscheck_returns_finite_ranked_attacks(self):
        report = estimate_upstream_isd(100, 50, 10)
        self.assertEqual(report.package_version, EXPECTED_UPSTREAM_VERSION)
        self.assertGreater(len(report.points), 3)
        self.assertEqual(
            tuple(point.time_bits for point in report.points),
            tuple(sorted(point.time_bits for point in report.points)),
        )
        names = {point.algorithm for point in report.points}
        self.assertIn("Prange", names)
        self.assertTrue(
            names.intersection({"Dumer", "BJMM", "BJMMplus", "BothMay", "MayOzerov"}),
            names,
        )
        self.assertLess(report.fastest.time_bits, report.by_algorithm("Prange").time_bits)


if __name__ == "__main__":
    unittest.main()
