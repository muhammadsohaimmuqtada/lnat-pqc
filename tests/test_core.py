import random
import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_core import LNATAutomaton, generate_input_sequence, observation_bit, prf
from lnat_params import LNAT128, LNAT256, LNATParams


class CoreTests(unittest.TestCase):
    def test_prf_is_deterministic(self):
        seed = bytes(range(32))
        self.assertEqual(prf(seed, b"test", 64), prf(seed, b"test", 64))
        self.assertNotEqual(prf(seed, b"test-a", 32), prf(seed, b"test-b", 32))

    def test_transition_then_observe_matches_spec(self):
        params = LNATParams("test-profile", n=32, m=4, T=1, eta=0.0, kappa=16)
        seed = bytes(range(32))
        automaton = LNATAutomaton(seed, params)
        q0 = automaton.derive_q0(b"nonce")
        inp = 7
        q1 = automaton.table.lookup(q0, inp)
        trace = automaton.run_noiseless(q0, [inp])
        self.assertEqual(trace, [observation_bit(q1, params)])

    def test_input_expansion_is_profile_domain_separated(self):
        seed_a = bytes.fromhex("00" * 32)
        _, a128 = generate_input_sequence(LNAT128, seed_a)
        _, a256 = generate_input_sequence(LNAT256, seed_a)
        self.assertNotEqual(a128[:16], a256[:16])

    def test_input_expansion_uses_full_16_bit_alphabet(self):
        seed_a = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
        _, values = generate_input_sequence(LNAT256, seed_a)
        self.assertTrue(all(0 <= value < 2**16 for value in values))
        self.assertTrue(any(value > 255 for value in values))

    def test_invalid_transition_input_rejected(self):
        seed = bytes(range(32))
        automaton = LNATAutomaton(seed, LNAT128)
        with self.assertRaises(ValueError):
            automaton.table.lookup(0, 2**LNAT128.m)
        with self.assertRaises(ValueError):
            automaton.table.lookup(2**LNAT128.n, 0)

    def test_noise_can_be_deterministic_in_tests(self):
        params = LNATParams("test-noise", n=32, m=4, T=8, eta=0.5, kappa=16)
        seed = bytes(range(32))
        automaton = LNATAutomaton(seed, params)
        q0 = automaton.derive_q0(b"nonce")
        inputs = list(range(8))
        rng1 = random.Random(7)
        rng2 = random.Random(7)
        self.assertEqual(
            automaton.run_noisy(q0, inputs, rng1),
            automaton.run_noisy(q0, inputs, rng2),
        )


if __name__ == "__main__":
    unittest.main()
