import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_modern_frontier import (
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
                memory_bits=max(0.0, time_bits - 20.0),
                parameters={"fixture": True},
            ),
        ),
    )


class ModernISDFrontierTests(unittest.TestCase):
    def test_rejects_candidate_below_modeled_attack_floor(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        candidate = evaluate_modern_isd_candidate(
            256,
            128,
            48,
            policy,
            estimate_fn=lambda n, k, w: fake_report(n, k, w, 21.46),
        )
        self.assertIsNone(candidate)

    def test_accepts_explicit_candidate_when_all_gates_pass(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        candidate = evaluate_modern_isd_candidate(
            1536,
            768,
            156,
            policy,
            estimate_fn=lambda n, k, w: fake_report(n, k, w, 164.82),
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate.fastest_algorithm, "MayOzerov")
        self.assertAlmostEqual(candidate.modeled_attack_time_bits, 164.82)
        self.assertLessEqual(candidate.conservative_kem_failure_bound, 1e-9)
        self.assertEqual(candidate.repetitions, 206)
        self.assertEqual(candidate.cutoff_ones, 56)

    def test_selection_uses_explicit_order_not_weight_monotonicity(self):
        policy = ModernISDPolicy(modeled_attack_floor_bits=128.0)
        estimates = {
            (256, 128, 28): 40.08,
            (256, 128, 48): 21.46,
            (1536, 768, 156): 164.82,
        }

        def estimate(n: int, k: int, w: int) -> UpstreamISDReport:
            return fake_report(n, k, w, estimates[(n, k, w)])

        candidate = select_first_modern_isd_candidate(
            [(256, 128, 28), (256, 128, 48), (1536, 768, 156)],
            policy,
            estimate_fn=estimate,
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual((candidate.n, candidate.k, candidate.secret_weight), (1536, 768, 156))

    def test_prange_prefilter_can_reject_before_estimator_call(self):
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
