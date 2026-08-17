import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_analysis import (
    direct_prf_trace,
    exhaustive_seed_recovery,
    exhaustive_seed_recovery_pruned,
    input_avalanche,
    make_observation,
    monobit_bias,
    score_seed,
    score_seed_bounded,
)
from lnat_params import LNATParams, TOY8


class AnalysisTests(unittest.TestCase):
    def test_exhaustive_recovery_finds_toy_seed_noiseless(self):
        params = LNATParams("toy-recovery", n=8, m=2, T=24, eta=0.0, seed_size=1)
        seed = b"\xa7"
        obs = make_observation(seed, params, nonce=b"N" * 8, seed_A=b"A" * 32, noisy=False)
        recovered, score, _ = exhaustive_seed_recovery([obs], params)
        self.assertEqual(recovered, seed)
        self.assertEqual(score, 0)

    def test_pruned_recovery_matches_exhaustive_under_noise(self):
        params = LNATParams("toy-pruned", n=8, m=2, T=24, eta=0.05, seed_size=1)
        seed = b"\x42"
        observations = [
            make_observation(
                seed,
                params,
                nonce=bytes([i + 1]) * 8,
                seed_A=bytes([20 + i]) * 32,
                noisy=True,
                rng=random.Random(100 + i),
            )
            for i in range(3)
        ]
        expected_seed, expected_score, _ = exhaustive_seed_recovery(observations, params)
        result = exhaustive_seed_recovery_pruned(observations, params)
        self.assertEqual(result.seed, expected_seed)
        self.assertEqual(result.score, expected_score)
        self.assertLessEqual(result.bit_comparisons, result.full_bit_comparisons)
        self.assertGreaterEqual(result.candidates_pruned, 0)

    def test_bounded_score_prunes_candidate_that_cannot_win(self):
        params = LNATParams("toy-bound", n=8, m=2, T=32, eta=0.0, seed_size=1)
        seed = b"\x33"
        obs = make_observation(seed, params, nonce=b"N" * 8, seed_A=b"B" * 32, noisy=False)
        score, compared, pruned = score_seed_bounded(
            b"\x99", [obs], params, cutoff=1
        )
        self.assertTrue(pruned)
        self.assertEqual(score, 1)
        self.assertLessEqual(compared, params.T)

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

    def test_direct_prf_baseline_is_deterministic(self):
        params = LNATParams("direct-test", n=32, m=4, T=32, eta=0.0, seed_size=32)
        seed = bytes(range(32))
        kwargs = dict(nonce=b"N" * 16, seed_A=b"A" * 32)
        self.assertEqual(
            direct_prf_trace(seed, params, **kwargs),
            direct_prf_trace(seed, params, **kwargs),
        )

    def test_input_mutation_propagates_only_through_lnat_state_chain(self):
        params = LNATParams("avalanche-test", n=32, m=4, T=64, eta=0.0, seed_size=32)
        result = input_avalanche(
            bytes(range(32)),
            params,
            nonce=b"N" * 16,
            seed_A=b"A" * 32,
            mutation_index=16,
        )
        self.assertEqual(result.tail_length, 47)
        self.assertEqual(result.direct_tail_differences, 0)
        self.assertGreater(result.lnat_tail_differences, 0)

    def test_monobit_bias_range(self):
        self.assertAlmostEqual(monobit_bias([0, 1, 0, 1]), 0.0)


if __name__ == "__main__":
    unittest.main()
