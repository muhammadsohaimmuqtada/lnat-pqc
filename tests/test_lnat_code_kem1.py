import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_outer_channel import OuterChannelCiphertext
from code_pke_reference import CodePKEParams
from code_segmented_outer import SegmentedOuterCiphertext
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem1 import (
    LNATCodeKEM1,
    LNATCodeKEM1Ciphertext,
    LNATCodeKEM1Params,
)
from lnat_params import LNATParams


TEST_PARAMS = LNATCodeKEM1Params(
    bridge=LNATCodeBridgeParams(
        code=CodePKEParams(
            n=64,
            k=32,
            secret_weight=2,
            encryption_error_weight=1,
            repetitions=96,
            zero_threshold=0.25,
        ),
        lnat=LNATParams(
            name="LNAT-code-kem1-test",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    ),
    encapsulated_seed_bytes=4,
    channel_uses_per_byte=128,
    confirmation_tag_bytes=16,
)


class LNATCodeKEM1Tests(unittest.TestCase):
    def setUp(self):
        self.kem = LNATCodeKEM1(TEST_PARAMS)

    def test_full_round_trip(self):
        pk, sk = self.kem.keygen(rng=random.Random(3101))
        ct, sender = self.kem.encap(pk, rng=random.Random(3102))
        receiver = self.kem.decap(sk, pk, ct)
        self.assertEqual(sender, receiver)
        self.assertEqual(len(sender), 32)
        self.assertEqual(pk.outer_code.total_channel_uses, 4 * 128)
        self.assertEqual(ct.size_bytes(), 4 * 128 * 8 + 16)

    def test_public_encapsulation_needs_no_secret_key(self):
        pk, _ = self.kem.keygen(rng=random.Random(3201))
        ct, key = self.kem.encap(pk, rng=random.Random(3202))
        self.assertEqual(len(ct.payload.blocks), TEST_PARAMS.encapsulated_seed_bytes)
        self.assertEqual(len(key), 32)

    def test_segmented_payload_is_about_six_times_smaller_than_repetition_fixture(self):
        pk, _ = self.kem.keygen(rng=random.Random(3301))
        ct, _ = self.kem.encap(pk, rng=random.Random(3302))
        word_bytes = (TEST_PARAMS.bridge.code.n + 7) // 8
        repetition_bytes = (
            TEST_PARAMS.encapsulated_seed_bits
            * TEST_PARAMS.bridge.code.repetitions
            * word_bytes
            + TEST_PARAMS.confirmation_tag_bytes
        )
        self.assertEqual(repetition_bytes, 24_592)
        self.assertEqual(ct.size_bytes(), 4_112)
        self.assertGreater(repetition_bytes / ct.size_bytes(), 5.9)

    def test_wrong_secret_key_rejected(self):
        pk, _ = self.kem.keygen(rng=random.Random(3401))
        _, wrong_sk = self.kem.keygen(rng=random.Random(3402))
        ct, _ = self.kem.encap(pk, rng=random.Random(3403))
        with self.assertRaises(ValueError):
            self.kem.decap(wrong_sk, pk, ct)

    def test_confirmation_tag_tamper_rejected(self):
        pk, sk = self.kem.keygen(rng=random.Random(3501))
        ct, _ = self.kem.encap(pk, rng=random.Random(3502))
        tag = bytes([ct.confirmation_tag[0] ^ 1]) + ct.confirmation_tag[1:]
        tampered = LNATCodeKEM1Ciphertext(ct.payload, tag, ct.params)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.kem.decap(sk, pk, tampered)

    def test_payload_tamper_rejected(self):
        pk, sk = self.kem.keygen(rng=random.Random(3601))
        ct, _ = self.kem.encap(pk, rng=random.Random(3602))
        first_block = ct.payload.blocks[0]
        words = list(first_block.words)
        words[0] ^= 1
        changed_first = OuterChannelCiphertext(tuple(words), first_block.params)
        payload = SegmentedOuterCiphertext(
            (changed_first, *ct.payload.blocks[1:]),
            ct.payload.params,
        )
        tampered = LNATCodeKEM1Ciphertext(payload, ct.confirmation_tag, ct.params)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.kem.decap(sk, pk, tampered)


if __name__ == "__main__":
    unittest.main()
