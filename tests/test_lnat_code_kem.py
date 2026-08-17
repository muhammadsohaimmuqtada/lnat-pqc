import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import CodePKECiphertext, CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem import LNATCodeKEM0, LNATCodeKEMCiphertext, LNATCodeKEMParams
from lnat_params import LNATParams


TEST_PARAMS = LNATCodeKEMParams(
    bridge=LNATCodeBridgeParams(
        code=CodePKEParams(
            n=64,
            k=32,
            secret_weight=2,
            encryption_error_weight=1,
            repetitions=64,
            zero_threshold=0.25,
        ),
        lnat=LNATParams(
            name="LNAT-code-kem-test",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    ),
    encapsulated_seed_bytes=2,
    confirmation_tag_bytes=16,
)


class LNATCodeKEMTests(unittest.TestCase):
    def setUp(self):
        self.kem = LNATCodeKEM0(TEST_PARAMS)

    def test_full_round_trip(self):
        pk, sk = self.kem.keygen(rng=random.Random(1101))
        ct, sender = self.kem.encap(pk, rng=random.Random(1102))
        receiver = self.kem.decap(sk, pk, ct)
        self.assertEqual(sender, receiver)
        self.assertEqual(len(sender), 32)
        self.assertGreater(ct.size_bytes(), 0)

    def test_encapsulation_requires_public_key_only(self):
        pk, _ = self.kem.keygen(rng=random.Random(1201))
        ct, key = self.kem.encap(pk, rng=random.Random(1202))
        self.assertEqual(len(ct.bit_ciphertexts), TEST_PARAMS.encapsulated_seed_bits)
        self.assertEqual(len(key), 32)

    def test_wrong_secret_key_rejected(self):
        pk, _ = self.kem.keygen(rng=random.Random(1301))
        _, wrong_sk = self.kem.keygen(rng=random.Random(1302))
        ct, _ = self.kem.encap(pk, rng=random.Random(1303))
        with self.assertRaises(ValueError):
            self.kem.decap(wrong_sk, pk, ct)

    def test_confirmation_tag_tamper_rejected(self):
        pk, sk = self.kem.keygen(rng=random.Random(1401))
        ct, _ = self.kem.encap(pk, rng=random.Random(1402))
        tampered_tag = bytes([ct.confirmation_tag[0] ^ 1]) + ct.confirmation_tag[1:]
        tampered = LNATCodeKEMCiphertext(ct.bit_ciphertexts, tampered_tag, ct.params)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.kem.decap(sk, pk, tampered)

    def test_ciphertext_body_tamper_rejected(self):
        pk, sk = self.kem.keygen(rng=random.Random(1501))
        ct, _ = self.kem.encap(pk, rng=random.Random(1502))
        first = ct.bit_ciphertexts[0]
        words = list(first.words)
        words[0] ^= 1
        changed_first = CodePKECiphertext(tuple(words), first.params)
        bit_ciphertexts = (changed_first, *ct.bit_ciphertexts[1:])
        tampered = LNATCodeKEMCiphertext(tuple(bit_ciphertexts), ct.confirmation_tag, ct.params)
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.kem.decap(sk, pk, tampered)

    def test_parameter_mismatch_rejected(self):
        other = LNATCodeKEM0(
            LNATCodeKEMParams(
                bridge=TEST_PARAMS.bridge,
                encapsulated_seed_bytes=1,
                confirmation_tag_bytes=16,
            )
        )
        pk, _ = self.kem.keygen(rng=random.Random(1601))
        with self.assertRaisesRegex(ValueError, "parameter mismatch"):
            other.encap(pk, rng=random.Random(1602))


if __name__ == "__main__":
    unittest.main()
