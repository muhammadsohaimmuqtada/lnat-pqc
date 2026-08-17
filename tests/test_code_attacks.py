import math
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_attacks import recover_sparse_error_from_public_key
from code_pke_reference import CodePKEParams, CodePKESecretKey, decrypt_bit, encrypt_bit, keygen


TOY = CodePKEParams(
    n=64,
    k=32,
    secret_weight=2,
    encryption_error_weight=2,
    repetitions=96,
    zero_threshold=0.25,
)


class CodeAttackTests(unittest.TestCase):
    def test_public_enumeration_recovers_exact_sparse_error(self):
        pk, sk = keygen(TOY, rng=random.Random(71))
        result = recover_sparse_error_from_public_key(pk)
        self.assertEqual(result.witness, sk.error)
        self.assertEqual(result.total_candidates, math.comb(TOY.n, TOY.secret_weight))
        self.assertGreaterEqual(result.candidates_tested, 1)
        self.assertLessEqual(result.candidates_tested, result.total_candidates)

    def test_recovered_public_witness_decrypts(self):
        pk, _ = keygen(TOY, rng=random.Random(81))
        result = recover_sparse_error_from_public_key(pk)
        attacker = CodePKESecretKey(result.witness, TOY)
        for bit in (0, 1):
            ct = encrypt_bit(pk, bit, rng=random.Random(90 + bit))
            self.assertEqual(decrypt_bit(attacker, ct), bit)

    def test_invalid_search_limit_rejected(self):
        pk, _ = keygen(TOY, rng=random.Random(91))
        with self.assertRaisesRegex(ValueError, "positive"):
            recover_sparse_error_from_public_key(pk, max_candidates=0)


if __name__ == "__main__":
    unittest.main()
