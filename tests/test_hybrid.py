import hashlib
import secrets
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_hybrid_kem import (
    HybridCiphertext,
    HybridPrivateKey,
    HybridPublicKey,
    LNATMLKEM768,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PRIVATE_SEED_BYTES,
    MLKEM768_PUBLIC_BYTES,
    MLKEM768_SHARED_SECRET_BYTES,
    derive_hybrid_key,
)
from lnat_params import LNATParams

TEST_PARAMS = LNATParams("LNAT-hybrid-test", n=32, m=4, T=64, eta=0.0, seed_size=32)


class FakeMLKEM768Backend:
    """Functional test double. Not cryptography."""

    @staticmethod
    def _public(seed: bytes) -> bytes:
        return hashlib.shake_256(b"fake-pk" + seed).digest(MLKEM768_PUBLIC_BYTES)

    def generate(self):
        seed = secrets.token_bytes(MLKEM768_PRIVATE_SEED_BYTES)
        return self._public(seed), seed

    def encapsulate(self, public_key: bytes):
        eph = secrets.token_bytes(32)
        padding = hashlib.shake_256(b"fake-ct" + public_key + eph).digest(
            MLKEM768_CIPHERTEXT_BYTES - 32
        )
        ct = eph + padding
        ss = hashlib.shake_256(b"fake-ss" + public_key + eph).digest(
            MLKEM768_SHARED_SECRET_BYTES
        )
        return ss, ct

    def decapsulate(self, private_seed: bytes, ciphertext: bytes):
        public = self._public(private_seed)
        return hashlib.shake_256(b"fake-ss" + public + ciphertext[:32]).digest(
            MLKEM768_SHARED_SECRET_BYTES
        )

    def public_from_private_seed(self, private_seed: bytes):
        return self._public(private_seed)


class HybridTests(unittest.TestCase):
    def setUp(self):
        self.kem = LNATMLKEM768(TEST_PARAMS, backend=FakeMLKEM768Backend())

    def test_round_trip(self):
        pk, sk = self.kem.keygen()
        ct, left = self.kem.encap(pk)
        right = self.kem.decap(sk, pk, ct)
        self.assertEqual(left, right)
        self.assertEqual(len(left), 32)

    def test_serialization_round_trip(self):
        pk, sk = self.kem.keygen()
        ct, _ = self.kem.encap(pk)
        self.assertEqual(HybridPublicKey.from_bytes(pk.to_bytes(), TEST_PARAMS), pk)
        self.assertEqual(HybridPrivateKey.from_bytes(sk.to_bytes(), TEST_PARAMS), sk)
        self.assertEqual(HybridCiphertext.from_bytes(ct.to_bytes()), ct)

    def test_wrong_private_key_rejected(self):
        pk, _ = self.kem.keygen()
        _, wrong_sk = self.kem.keygen()
        ct, _ = self.kem.encap(pk)
        with self.assertRaises(ValueError):
            self.kem.decap(wrong_sk, pk, ct)

    def test_context_tag_tamper_rejected(self):
        pk, sk = self.kem.keygen()
        ct, _ = self.kem.encap(pk)
        tampered = HybridCiphertext(
            ct.mlkem_ciphertext,
            bytes([ct.public_context_tag[0] ^ 1]) + ct.public_context_tag[1:],
        )
        with self.assertRaisesRegex(ValueError, "different public context"):
            self.kem.decap(sk, pk, tampered)

    def test_lnat_postprocessing_changes_raw_secret(self):
        pk, _ = self.kem.keygen()
        raw, ct = self.kem.backend.encapsulate(pk.mlkem_public)
        final = derive_hybrid_key(raw, pk, ct)
        self.assertNotEqual(raw, final)


if __name__ == "__main__":
    unittest.main()
