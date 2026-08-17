import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import assess_modern_candidate
from code_sd_estimator import upstream_available


@unittest.skipUnless(upstream_available(), "pinned cryptographic-estimators extra not installed")
class RealModernFrontierIntegrationTests(unittest.TestCase):
    def test_rejected_n256_w28_reference_point(self):
        assessment = assess_modern_candidate(
            256,
            128,
            28,
            max_repetitions=512,
        )
        self.assertEqual(assessment.upstream_package_version, "2.1.1")
        self.assertEqual(assessment.upstream_algorithm, "MayOzerov")
        self.assertAlmostEqual(assessment.upstream_time_bits, 40.081937, places=5)
        self.assertEqual(assessment.effective_attack, "MayOzerov")
        self.assertAlmostEqual(assessment.effective_attack_bits, 40.081937, places=5)
        self.assertGreater(assessment.support_enumeration_bits, assessment.effective_attack_bits)
        self.assertEqual(assessment.repetitions, 220)
        self.assertEqual(assessment.cutoff_ones, 61)
        self.assertLessEqual(assessment.conservative_kem_failure_bound, 1e-9)


if __name__ == "__main__":
    unittest.main()
