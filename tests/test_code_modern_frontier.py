import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import (
    ACTIVE_RESEARCH_POINT,
    BELOW_FLOOR_NEIGHBOR,
    ModernISDPolicy,
    evaluate_modern_isd_candidate,
    select_first_modern_isd_candidate,
)
from code_sd_estimator import UpstreamISDPoint, UpstreamISDReport


def fake_report(n: int, k: int, w: int, time_bits: float) -> UpstreamISDReport:
    return UpstreamISDReport(
        n=n,
        k=k,
        weight=w,
        package_version="test-estimator",
        points=(
            UpstreamISDPoint(
                algorithm="MayOzerov",
                time_bits=time_bits,
                memory_bits=max(0.0, time_bits - 30.0),
                parameters={"fixture": True},
            ),
        ),
    )


class ModernISDFrontierTests(unittest.TestCase):
    def test_measured_neighbor_below_floor_is_rejected(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        n, k, w = BELOW_FLOOR_NEIGHBOR
        candidate = evaluate_modern_isd_candidate(
            n,
            k,
            w,
            policy,
            estimate_fn=lambda n, k, w: fake_report(n, k, w, 127.668792),
        )
        self.assertIsNone(candidate)

    def test_measured_active_research_point_clears_screen(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        n, k, w = ACTIVE_RESEARCH_POINT
        candidate = evaluate_modern_isd_candidate(
            n,
            k,
            w,
            policy,
            estimate_fn=lambda n, k, w: fake_report(n, k, w, 128.614772),
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual((candidate.n, candidate.k, candidate.secret_weight), ACTIVE_RESEARCH_POINT)
        self.assertEqual(candidate.upstream_fastest_algorithm, "MayOzerov")
        self.assertAlmostEqual(candidate.effective_attack_bits, 128.614772)
        self.assertEqual(candidate.effective_attack, "MayOzerov")
        self.assertEqual(candidate.repetitions, 220)
        self.assertEqual(candidate.cutoff_ones, 61)
        self.assertLessEqual(candidate.conservative_kem_failure_bound, 1e-9)

    def test_support_enumeration_is_an_independent_upper_bound(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=20.0)
        candidate = evaluate_modern_isd_candidate(
            64,
            32,
            2,
            policy,
            estimate_fn=lambda n, k, w: fake_report(n, k, w, 200.0),
        )
        self.assertIsNone(candidate)

    def test_selection_uses_explicit_order_not_weight_monotonicity(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        estimates = {
            BELOW_FLOOR_NEIGHBOR: 127.668792,
            ACTIVE_RESEARCH_POINT: 128.614772,
            (1088, 544, 119): 130.539624,
        }

        def estimate(n: int, k: int, w: int) -> UpstreamISDReport:
            return fake_report(n, k, w, estimates[(n, k, w)])

        candidate = select_first_modern_isd_candidate(
            [BELOW_FLOOR_NEIGHBOR, ACTIVE_RESEARCH_POINT, (1088, 544, 119)],
            policy,
            estimate_fn=estimate,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual((candidate.n, candidate.k, candidate.secret_weight), ACTIVE_RESEARCH_POINT)

    def test_prange_prefilter_rejects_before_estimator_call(self):
        policy = ModernISDPolicy(
            modeled_attack_floor_bits=1.0,
            prange_prefilter_bits=10_000.0,
        )
        calls = 0

        def should_not_run(n: int, k: int, w: int) -> UpstreamISDReport:
            nonlocal calls
            calls += 1
            return fake_report(n, k, w, 999.0)

        self.assertIsNone(
            evaluate_modern_isd_candidate(
                256,
                128,
                28,
                policy,
                estimate_fn=should_not_run,
            )
        )
        self.assertEqual(calls, 0)

    def test_invalid_policy_and_point_rejected(self):
        with self.assertRaises(ValueError):
            ModernISDPolicy(modeled_attack_floor_bits=-1)
        policy = ModernISDPolicy(modeled_attack_floor_bits=128)
        with self.assertRaises(ValueError):
            evaluate_modern_isd_candidate(64, 64, 2, policy)
        with self.assertRaises(ValueError):
            evaluate_modern_isd_candidate(64, 32, 33, policy)


if __name__ == "__main__":
    unittest.main()
