import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_channel_audit import (
    audit_repetition_efficiency,
    binary_entropy,
    code_bit_channel_capacity,
    minimum_channel_uses_by_capacity,
)
from code_pke_reference import CodePKEParams


FRONTIER = CodePKEParams(
    n=256,
    k=128,
    secret_weight=30,
    encryption_error_weight=1,
    repetitions=233,
    zero_threshold=66 / 233,
)


class CodeChannelAuditTests(unittest.TestCase):
    def test_binary_entropy_edges_and_half(self):
        self.assertEqual(binary_entropy(0.0), 0.0)
        self.assertEqual(binary_entropy(1.0), 0.0)
        self.assertAlmostEqual(binary_entropy(0.5), 1.0)

    def test_frontier_channel_capacity_regression(self):
        channel = code_bit_channel_capacity(30 / 256)
        self.assertAlmostEqual(channel.capacity_bits_per_use, 0.13148607449367572)
        self.assertAlmostEqual(channel.optimal_input_one_probability, 0.4668352729725102)
        self.assertAlmostEqual(channel.output_one_probability_at_capacity, 0.29589787793478906)

    def test_toy_outer_channel_capacity_regression(self):
        # secret weight 2, fresh error weight 1, n=64 -> q=2/64=1/32.
        channel = code_bit_channel_capacity(1 / 32)
        self.assertAlmostEqual(channel.capacity_bits_per_use, 0.23854135781873376)
        self.assertGreater(channel.capacity_bits_per_use, 8 / 48)

    def test_capacity_lower_bound_for_128_bit_seed(self):
        channel = code_bit_channel_capacity(30 / 256)
        self.assertEqual(
            minimum_channel_uses_by_capacity(128, channel.capacity_bits_per_use),
            974,
        )

    def test_repetition_is_far_above_capacity_floor(self):
        audit = audit_repetition_efficiency(
            FRONTIER,
            message_bits=128,
            confirmation_tag_bytes=16,
        )
        self.assertEqual(audit.word_bytes, 32)
        self.assertEqual(audit.repetition_channel_uses, 29_824)
        self.assertEqual(audit.capacity_lower_bound_channel_uses, 974)
        self.assertEqual(audit.repetition_ciphertext_bytes, 954_384)
        self.assertEqual(audit.capacity_lower_bound_ciphertext_bytes, 31_184)
        self.assertGreater(audit.channel_use_overhead_ratio, 30.0)
        self.assertGreater(audit.ciphertext_overhead_ratio, 30.0)
        self.assertLess(audit.ciphertext_overhead_ratio, 31.0)

    def test_invalid_capacity_inputs_rejected(self):
        with self.assertRaises(ValueError):
            code_bit_channel_capacity(0.5)
        with self.assertRaises(ValueError):
            binary_entropy(-0.1)
        with self.assertRaises(ValueError):
            minimum_channel_uses_by_capacity(0, 0.1)
        with self.assertRaises(ValueError):
            minimum_channel_uses_by_capacity(128, 0.0)


if __name__ == "__main__":
    unittest.main()
