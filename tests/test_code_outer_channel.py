import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_outer_channel import (
    decrypt_bridge_outer_message,
    generate_outer_linear_code,
    encrypt_bridge_outer_message,
)
from code_pke_reference import CodePKEParams, gf2_rank
from lnat_code_bridge import LNATCodeBridgeParams, keygen
from lnat_params import LNATParams


BRIDGE = LNATCodeBridgeParams(
    code=CodePKEParams(
        n=64,
        k=32,
        secret_weight=2,
        encryption_error_weight=1,
        repetitions=96,
        zero_threshold=0.25,
    ),
    lnat=LNATParams(
        name="LNAT-outer-channel-test",
        n=32,
        m=4,
        T=32,
        eta=0.0,
        seed_size=32,
    ),
)


class OuterChannelTests(unittest.TestCase):
    def test_outer_code_is_full_rank_and_dense_in_coordinates(self):
        outer = generate_outer_linear_code(8, 128, rng=random.Random(301))
        self.assertEqual(gf2_rank(outer.generator_rows, outer.channel_uses), 8)
        self.assertAlmostEqual(outer.rate, 8 / 128)
        for column in range(outer.channel_uses):
            self.assertTrue(any((row >> column) & 1 for row in outer.generator_rows))

    def test_public_bridge_round_trip_multiple_messages(self):
        pk, sk = keygen(BRIDGE, rng=random.Random(311))
        outer = generate_outer_linear_code(8, 128, rng=random.Random(312))
        messages = (0x00, 0x01, 0x2A, 0x55, 0x80, 0xA5, 0xFE, 0xFF)
        for index, message in enumerate(messages):
            ct = encrypt_bridge_outer_message(
                pk,
                outer,
                message,
                rng=random.Random(400 + index),
            )
            recovered = decrypt_bridge_outer_message(sk, pk, ct, outer)
            self.assertEqual(recovered, message)
            self.assertEqual(ct.channel_uses, 128)
            self.assertEqual(ct.size_bytes(), 1024)

    def test_outer_code_reduces_word_count_vs_repetition_fixture(self):
        outer = generate_outer_linear_code(8, 128, rng=random.Random(321))
        repetition_words = 8 * BRIDGE.code.repetitions
        self.assertEqual(repetition_words, 768)
        self.assertEqual(outer.channel_uses, 128)
        self.assertEqual(repetition_words / outer.channel_uses, 6.0)

    def test_message_out_of_range_rejected(self):
        outer = generate_outer_linear_code(8, 128, rng=random.Random(331))
        with self.assertRaises(ValueError):
            outer.encode(256)

    def test_exhaustive_ml_limit_is_explicit(self):
        with self.assertRaisesRegex(ValueError, "exhaustive ML"):
            generate_outer_linear_code(17, 256, rng=random.Random(341))


if __name__ == "__main__":
    unittest.main()
