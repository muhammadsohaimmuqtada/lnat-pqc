import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_post_quantum_frontier import (
    assess_post_quantum_candidate,
    screen_post_quantum_candidate,
)
from code_sd_estimator import UpstreamISDPoint, UpstreamISDReport


def fake_estimator(time_bits: float, *, algorithm: str = "FakeModern"):
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
                    memory_bits=12.0,
                    parameters={"source": "unit-test"},
                ),
            ),
        )
    return estimate


class PostQuantumFrontierTests(unittest.TestCase):
    def test_current_classical_frontier_is_rejected_by_quantum_gate(self):
        assessment = assess_post_quantum_candidate(
            1064,
            532,
            117,
            max_repetitions=512,
            classical_estimator=fake_estimator(128.611921, algorithm="MayOzerov"),
        )
        self.assertTrue(assessment.classical.passes(128.0, 1e-9))
        self.assertFalse(assessment.quantum.passes_iteration_floor(128.0))
        self.assertFalse(
            assessment.passes(
                classical_attack_floor_bits=128.0,
                quantum_iteration_floor_bits=128.0,
                kem_failure_ceiling=1e-9,
            )
        )
        self.assertIsNone(
            screen_post_quantum_candidate(
                1064,
                532,
                117,
                classical_attack_floor_bits=128.0,
                quantum_iteration_floor_bits=128.0,
                max_repetitions=512,
                classical_estimator=fake_estimator(128.611921, algorithm="MayOzerov"),
            )
        )

    def test_all_gates_can_pass_at_low_test_floors(self):
        assessment = screen_post_quantum_candidate(
            256,
            128,
            28,
            classical_attack_floor_bits=40.0,
            quantum_iteration_floor_bits=15.0,
            max_repetitions=512,
            classical_estimator=fake_estimator(40.1),
        )
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.classical.effective_attack_bits, 40.0)
        self.assertGreaterEqual(assessment.quantum.effective_quantum_search_bits, 15.0)
        self.assertLessEqual(assessment.classical.conservative_kem_failure_bound, 1e-9)

    def test_classical_failure_still_rejects(self):
        self.assertIsNone(
            screen_post_quantum_candidate(
                256,
                128,
                28,
                classical_attack_floor_bits=41.0,
                quantum_iteration_floor_bits=15.0,
                max_repetitions=512,
                classical_estimator=fake_estimator(40.0),
            )
        )

    def test_invalid_floors_rejected(self):
        assessment = assess_post_quantum_candidate(
            256,
            128,
            28,
            max_repetitions=512,
            classical_estimator=fake_estimator(40.0),
        )
        with self.assertRaises(ValueError):
            assessment.passes(
                classical_attack_floor_bits=-1.0,
                quantum_iteration_floor_bits=1.0,
                kem_failure_ceiling=1e-9,
            )
        with self.assertRaises(TypeError):
            screen_post_quantum_candidate(
                256,
                128,
                28,
                classical_attack_floor_bits=40.0,
                quantum_iteration_floor_bits=True,
                classical_estimator=fake_estimator(40.0),
            )


if __name__ == "__main__":
    unittest.main()
