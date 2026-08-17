import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import assess_modern_candidate, screen_modern_candidate
from code_profile_audit import sparse_witness_enumeration_bits
from code_sd_estimator import UpstreamISDPoint, UpstreamISDReport


def fake_estimator(time_bits: float, *, algorithm: str = "FakeModern", memory_bits: float = 12.0):
    def estimate(n: int, k: int, weight: int) -> UpstreamISDReport:
        return UpstreamISDReport(
            n=n,
            k=k,
            weight=weight,
            package_version="test-double",
            points=(
                UpstreamISDPoint(
                    algorithm=algorithm,
                    time_bits=time_bits,
                    memory_bits=memory_bits,
                    parameters={"source": "unit-test"},
                ),
            ),
        )

    return estimate


class ModernFrontierTests(unittest.TestCase):
    def test_upstream_estimator_is_effective_attack_when_cheaper(self):
        assessment = assess_modern_candidate(
            256,
            128,
            28,
            estimator=fake_estimator(40.0, algorithm="MayOzerov"),
            max_repetitions=512,
        )
        self.assertEqual(assessment.effective_attack, "MayOzerov")
        self.assertEqual(assessment.effective_attack_bits, 40.0)
        self.assertGreater(assessment.support_enumeration_bits, 40.0)
        self.assertTrue(assessment.correctness_feasible)
        self.assertEqual(assessment.repetitions, 220)
        self.assertEqual(assessment.cutoff_ones, 61)
        self.assertLessEqual(assessment.conservative_kem_failure_bound, 1e-9)

    def test_support_enumeration_caps_overoptimistic_estimator(self):
        support = sparse_witness_enumeration_bits(256, 28)
        assessment = assess_modern_candidate(
            256,
            128,
            28,
            estimator=fake_estimator(support + 100.0),
            max_repetitions=512,
        )
        self.assertEqual(assessment.effective_attack, "SupportEnumeration")
        self.assertAlmostEqual(assessment.effective_attack_bits, support)

    def test_screen_requires_effective_attack_floor(self):
        estimator = fake_estimator(40.0)
        accepted = screen_modern_candidate(
            256,
            128,
            28,
            attack_floor_bits=40.0,
            estimator=estimator,
            max_repetitions=512,
        )
        rejected = screen_modern_candidate(
            256,
            128,
            28,
            attack_floor_bits=40.0001,
            estimator=estimator,
            max_repetitions=512,
        )
        self.assertIsNotNone(accepted)
        self.assertIsNone(rejected)

    def test_screen_rejects_correctness_infeasible_limit(self):
        assessment = assess_modern_candidate(
            256,
            128,
            28,
            estimator=fake_estimator(200.0),
            max_repetitions=1,
        )
        self.assertFalse(assessment.correctness_feasible)
        self.assertIsNone(
            screen_modern_candidate(
                256,
                128,
                28,
                attack_floor_bits=1.0,
                estimator=fake_estimator(200.0),
                max_repetitions=1,
            )
        )

    def test_invalid_candidate_rejected(self):
        with self.assertRaises(ValueError):
            assess_modern_candidate(64, 64, 4, estimator=fake_estimator(10))
        with self.assertRaises(ValueError):
            assess_modern_candidate(64, 32, 33, estimator=fake_estimator(10))
        with self.assertRaises(ValueError):
            screen_modern_candidate(
                64,
                32,
                4,
                attack_floor_bits=-1,
                estimator=fake_estimator(10),
            )


if __name__ == "__main__":
    unittest.main()
