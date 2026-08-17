import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_outer_channel import generate_outer_linear_code
from code_outer_sim import (
    sample_channel_observation,
    simulate_outer_code,
    sweep_outer_code_lengths,
)


class OuterChannelSimulationTests(unittest.TestCase):
    def test_zero_symbol_is_noiseless_when_q_is_zero(self):
        outer = generate_outer_linear_code(4, 32, rng=random.Random(1))
        observed = sample_channel_observation(
            0,
            outer,
            zero_one_probability=0.0,
            rng=random.Random(2),
        )
        self.assertEqual(observed, 0)

    def test_simulation_is_deterministic_for_fixed_seeds(self):
        outer = generate_outer_linear_code(8, 96, rng=random.Random(3))
        left = simulate_outer_code(
            outer,
            zero_one_probability=1 / 32,
            trials=32,
            message_seed=4,
            channel_seed=5,
        )
        right = simulate_outer_code(
            outer,
            zero_one_probability=1 / 32,
            trials=32,
            message_seed=4,
            channel_seed=5,
        )
        self.assertEqual(left, right)
        self.assertAlmostEqual(left.rate, 8 / 96)
        self.assertGreater(left.channel_capacity_bits_per_use, left.rate)

    def test_sweep_returns_requested_lengths(self):
        points = sweep_outer_code_lengths(
            message_bits=4,
            channel_uses=(24, 32, 40),
            zero_one_probability=1 / 32,
            trials=16,
        )
        self.assertEqual(tuple(point.channel_uses for point in points), (24, 32, 40))
        self.assertTrue(all(point.trials == 16 for point in points))
        self.assertTrue(all(0 <= point.failures <= 16 for point in points))

    def test_invalid_lengths_rejected(self):
        with self.assertRaises(ValueError):
            sweep_outer_code_lengths(
                message_bits=8,
                channel_uses=(8, 16),
                zero_one_probability=1 / 32,
                trials=8,
            )


if __name__ == "__main__":
    unittest.main()
