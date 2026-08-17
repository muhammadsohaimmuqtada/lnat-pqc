import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_isd import (
    best_lee_brickell_cost,
    lee_brickell_cost_point,
    lee_brickell_success_probability,
    recover_sparse_error_lee_brickell,
)
from code_pke_reference import (
    CodePKEParams,
    CodePKESecretKey,
    keygen,
    public_secret_orthogonality_holds,
)


TOY = CodePKEParams(
    n=32,
    k=16,
    secret_weight=3,
    encryption_error_weight=1,
    repetitions=48,
    zero_threshold=0.25,
)


def assert_valid_public_witness(testcase, pk, witness):
    candidate = CodePKESecretKey(witness, TOY)
    testcase.assertEqual(witness.bit_count(), TOY.secret_weight)
    testcase.assertTrue(public_secret_orthogonality_holds(pk, candidate))


class LeeBrickellISDTests(unittest.TestCase):
    def test_p_zero_is_prange_event(self):
        probability = lee_brickell_success_probability(32, 16, 3, 0)
        self.assertAlmostEqual(probability, 560 / 4960)

    def test_one_error_guess_improves_information_set_success(self):
        p0 = lee_brickell_success_probability(32, 16, 3, 0)
        p1 = lee_brickell_success_probability(32, 16, 3, 1)
        self.assertGreater(p1, p0)
        self.assertAlmostEqual(p1, (16 * 120) / 4960)

    def test_naive_operation_model_selects_p_one_for_toy(self):
        p0 = lee_brickell_cost_point(32, 16, 3, 0)
        p1 = lee_brickell_cost_point(32, 16, 3, 1)
        best = best_lee_brickell_cost(32, 16, 3, max_p=3)
        self.assertEqual(best.p, 1)
        self.assertLess(p1.estimated_total_ops, p0.estimated_total_ops)
        self.assertLess(p1.expected_information_sets, p0.expected_information_sets)
        self.assertGreater(p1.guesses_per_invertible_set, p0.guesses_per_invertible_set)

    def test_executable_p_one_attack_recovers_valid_public_witness(self):
        pk, _ = keygen(TOY, rng=random.Random(501))
        result = recover_sparse_error_lee_brickell(
            pk,
            p=1,
            rng=random.Random(502),
            max_information_sets=256,
        )
        assert_valid_public_witness(self, pk, result.witness)
        self.assertEqual(result.p, 1)
        self.assertGreaterEqual(result.information_sets_sampled, 1)
        self.assertGreaterEqual(result.invertible_information_sets, 1)
        self.assertGreaterEqual(result.guesses_tested, 1)

    def test_p_zero_attack_still_recovers_valid_prange_witness(self):
        pk, _ = keygen(TOY, rng=random.Random(601))
        result = recover_sparse_error_lee_brickell(
            pk,
            p=0,
            rng=random.Random(602),
            max_information_sets=1024,
        )
        assert_valid_public_witness(self, pk, result.witness)
        self.assertEqual(result.p, 0)

    def test_invalid_p_rejected(self):
        pk, _ = keygen(TOY, rng=random.Random(701))
        with self.assertRaises(ValueError):
            recover_sparse_error_lee_brickell(pk, p=4)
        with self.assertRaises(ValueError):
            best_lee_brickell_cost(32, 16, 3, max_p=-1)


if __name__ == "__main__":
    unittest.main()
