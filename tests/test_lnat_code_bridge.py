import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKEParams
from lnat_code_bridge import (
    LNATCodeBridgeParams,
    LNATCodeBridgeSecretKey,
    decrypt_bit,
    derive_sparse_witness,
    encrypt_bit,
    keygen,
    recover_code_secret,
)
from lnat_params import LNATParams


BRIDGE = LNATCodeBridgeParams(
    code=CodePKEParams(
        n=64,
        k=32,
        secret_weight=2,
        encryption_error_weight=2,
        repetitions=96,
        zero_threshold=0.25,
    ),
    lnat=LNATParams(
        name="LNAT-bridge-toy",
        n=32,
        m=4,
        T=32,
        eta=0.0,
        seed_size=32,
    ),
)


class LNATCodeBridgeTests(unittest.TestCase):
    def test_witness_derivation_is_deterministic_and_exact_weight(self):
        seed = bytes(range(32))
        kwargs = dict(nonce=b"N" * 16, input_seed=b"A" * 32)
        left = derive_sparse_witness(seed, BRIDGE, **kwargs)
        right = derive_sparse_witness(seed, BRIDGE, **kwargs)
        self.assertEqual(left, right)
        self.assertEqual(left.bit_count(), BRIDGE.code.secret_weight)

    def test_public_schedule_changes_witness_distribution(self):
        seed = bytes(range(32))
        witnesses = {
            derive_sparse_witness(
                seed,
                BRIDGE,
                nonce=b"N" * 16,
                input_seed=bytes([index]) * 32,
            )
            for index in range(8)
        }
        self.assertGreater(len(witnesses), 1)

    def test_round_trip_requires_only_public_key_for_encryption(self):
        pk, sk = keygen(BRIDGE, rng=random.Random(31))
        for bit in (0, 1):
            ct = encrypt_bit(pk, bit, rng=random.Random(100 + bit))
            self.assertEqual(decrypt_bit(sk, pk, ct), bit)

    def test_wrong_lnat_seed_is_rejected_by_public_relation(self):
        pk, sk = keygen(BRIDGE, rng=random.Random(41))
        wrong_seed = bytes(byte ^ 0xFF for byte in sk.lnat_seed)
        wrong = LNATCodeBridgeSecretKey(wrong_seed, BRIDGE)
        with self.assertRaisesRegex(ValueError, "does not match"):
            recover_code_secret(wrong, pk)

    def test_secret_seed_regenerates_sparse_code_witness(self):
        pk, sk = keygen(BRIDGE, rng=random.Random(51))
        code_secret = recover_code_secret(sk, pk)
        self.assertEqual(code_secret.error.bit_count(), BRIDGE.code.secret_weight)

    def test_seed_length_does_not_overstate_sparse_witness_entropy(self):
        self.assertLess(BRIDGE.witness_space_bits, 16.0)
        self.assertEqual(BRIDGE.lnat.seed_size * 8, 256)


if __name__ == "__main__":
    unittest.main()
