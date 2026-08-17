import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import (
    CodePKEParams,
    decrypt_bit,
    decryption_statistic,
    encrypt_bit,
    gf2_rank,
    inner_product,
    keygen,
    public_dual_basis,
    public_secret_orthogonality_holds,
)


TOY = CodePKEParams(
    n=64,
    k=32,
    secret_weight=2,
    encryption_error_weight=2,
    repetitions=96,
    zero_threshold=0.25,
)


class CodePKEReferenceTests(unittest.TestCase):
    def test_public_key_encodes_hidden_sparse_error_relation(self):
        pk, sk = keygen(TOY, rng=random.Random(7))
        self.assertEqual(gf2_rank(pk.generator, TOY.n), TOY.k)
        self.assertEqual(gf2_rank((*pk.generator, pk.noisy_codeword), TOY.n), TOY.k + 1)
        self.assertEqual(sk.error.bit_count(), TOY.secret_weight)
        self.assertTrue(public_secret_orthogonality_holds(pk, sk))

    def test_every_public_dual_vector_is_orthogonal_to_secret_error(self):
        pk, sk = keygen(TOY, rng=random.Random(11))
        dual = public_dual_basis(pk)
        self.assertEqual(len(dual), TOY.n - TOY.k - 1)
        self.assertTrue(all(inner_product(vector, sk.error) == 0 for vector in dual))

    def test_bit_round_trip(self):
        pk, sk = keygen(TOY, rng=random.Random(17))
        ct0 = encrypt_bit(pk, 0, rng=random.Random(18))
        ct1 = encrypt_bit(pk, 1, rng=random.Random(19))
        self.assertEqual(decrypt_bit(sk, ct0), 0)
        self.assertEqual(decrypt_bit(sk, ct1), 1)
        self.assertLess(decryption_statistic(sk, ct0), TOY.zero_threshold)
        self.assertGreaterEqual(decryption_statistic(sk, ct1), TOY.zero_threshold)

    def test_repeated_deterministic_trials_decode(self):
        failures = 0
        for trial in range(20):
            pk, sk = keygen(TOY, rng=random.Random(1000 + trial))
            for bit in (0, 1):
                ct = encrypt_bit(pk, bit, rng=random.Random(2000 + 2 * trial + bit))
                failures += decrypt_bit(sk, ct) != bit
        self.assertEqual(failures, 0)


if __name__ == "__main__":
    unittest.main()
