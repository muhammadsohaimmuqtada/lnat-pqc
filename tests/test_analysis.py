import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import exhaustive_seed_recovery, make_observation, monobit_bias, score_seed
from lnat_params import LNATParams, TOY8


class AnalysisTests(unittest.TestCase):
    def test_exhaustive_recovery_finds_toy_seed_noiseless(self):
        params = LNATParams("toy-recovery", n=8, m=2, T=24, eta=0.0, seed_size=1)
        seed = b"\xa7"
        obs = make_observation(seed, params, nonce=b"N" * 8, seed_A=b"A" * 32, noisy=False)
        recovered, score, _ = exhaustive_seed_recovery([obs], params)
        self.assertEqual(recovered, seed)
        self.assertEqual(score, 0)

    def test_multi_trace_scoring_prefers_true_seed_under_noise(self):
        seed = b"\x42"
        observations = [
            make_observation(
                seed,
                TOY8,
                nonce=bytes([i + 1]) * 8,
                seed_A=bytes([20 + i]) * 32,
                noisy=True,
                rng=random.Random(100 + i),
            )
            for i in range(4)
        ]
        true_score = score_seed(seed, observations, TOY8)
        wrong_score = score_seed(b"\x99", observations, TOY8)
        self.assertLess(true_score, wrong_score)

    def test_monobit_bias_range(self):
        self.assertAlmostEqual(monobit_bias([0, 1, 0, 1]), 0.0)


if __name__ == "__main__":
    unittest.main()
