import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_pke_reference import gf2_rank, gf2_rref, random_full_rank_code


def slow_reference_generator(n: int, k: int, seed: int) -> tuple[int, ...]:
    rng = random.Random(seed)
    rows: list[int] = []
    rank = 0
    while rank < k:
        candidate = rng.getrandbits(n)
        if candidate == 0:
            continue
        new_rank = len(gf2_rref((*rows, candidate), n)[1])
        if new_rank > rank:
            rows.append(candidate)
            rank = new_rank
    return tuple(rows)


class IncrementalGF2RankTests(unittest.TestCase):
    def test_rank_matches_rref_rank(self):
        rng = random.Random(1701)
        for n in (8, 17, 32, 65):
            rows = tuple(rng.getrandbits(n) for _ in range(n // 2 + 3))
            self.assertEqual(gf2_rank(rows, n), len(gf2_rref(rows, n)[1]))

    def test_generator_preserves_reference_acceptance_sequence(self):
        expected = slow_reference_generator(32, 16, 8128)
        actual = random_full_rank_code(32, 16, rng=random.Random(8128))
        self.assertEqual(actual, expected)

    def test_large_candidate_geometry_reaches_requested_rank(self):
        rows = random_full_rank_code(1064, 532, rng=random.Random(1064))
        self.assertEqual(len(rows), 532)
        self.assertEqual(gf2_rank(rows, 1064), 532)

    def test_rank_validation_is_preserved(self):
        with self.assertRaises(ValueError):
            gf2_rank([1], 0)
        with self.assertRaises(ValueError):
            gf2_rank([1 << 8], 8)


if __name__ == "__main__":
    unittest.main()
