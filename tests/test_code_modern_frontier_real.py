import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import assess_modern_candidate, screen_modern_candidate
from code_sd_estimator import upstream_available


@unittest.skipUnless(upstream_available(), "pinned cryptographic-estimators extra not installed")
class RealModernFrontierIntegrationTests(unittest.TestCase):
    def test_n1064_is_below_128_bit_modeled_screen(self):
        assessment = assess_modern_candidate(
            1064,
            532,
            116,
        )
        self.assertEqual(assessment.upstream_package_version, "2.1.1")
        self.assertEqual(assessment.upstream_algorithm, "MayOzerov")
        self.assertAlmostEqual(assessment.upstream_time_bits, 127.612109, places=5)
        self.assertEqual(assessment.effective_attack, "MayOzerov")
        self.assertAlmostEqual(assessment.effective_attack_bits, 127.612109, places=5)
        self.assertEqual(assessment.repetitions, 217)
        self.assertEqual(assessment.cutoff_ones, 60)
        self.assertLessEqual(assessment.conservative_kem_failure_bound, 1e-9)
        self.assertIsNone(
            screen_modern_candidate(
                1064,
                532,
                116,
                attack_floor_bits=128.0,
            )
        )

    def test_n1072_is_first_passing_point_in_measured_bracket(self):
        assessment = assess_modern_candidate(
            1072,
            536,
            117,
        )
        self.assertEqual(assessment.upstream_package_version, "2.1.1")
        self.assertEqual(assessment.upstream_algorithm, "MayOzerov")
        self.assertAlmostEqual(assessment.upstream_time_bits, 128.614772, places=5)
        self.assertEqual(assessment.effective_attack, "MayOzerov")
        self.assertAlmostEqual(assessment.effective_attack_bits, 128.614772, places=5)
        self.assertGreater(assessment.support_enumeration_bits, assessment.effective_attack_bits)
        self.assertEqual(assessment.repetitions, 220)
        self.assertEqual(assessment.cutoff_ones, 61)
        self.assertLessEqual(assessment.conservative_kem_failure_bound, 1e-9)
        self.assertIsNotNone(
            screen_modern_candidate(
                1072,
                536,
                117,
                attack_floor_bits=128.0,
            )
        )


if __name__ == "__main__":
    unittest.main()
