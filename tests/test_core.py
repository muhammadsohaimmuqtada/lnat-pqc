import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_core import LNATAutomaton, generate_input_sequence, observation_bit, prf
from lnat_params import LNAT128, LNAT256, LNATParams


class CoreTests(unittest.TestCase):
    def test_prf_domain_separation(self):
        seed = bytes(range(32))
        self.assertEqual(prf(seed, b"test", 64), prf(seed, b"test", 64))
        self.assertNotEqual(prf(seed, b"test-a", 32), prf(seed, b"test-b", 32))

    def test_transition_then_keyed_observe_matches_spec(self):
        params = LNATParams("test-exp2", n=32, m=4, T=1, eta=0.0, kappa=16)
        seed = bytes(range(32))
        automaton = LNATAutomaton(seed, params)
        q0 = automaton.derive_q0(b"nonce")
        q1 = automaton.table.lookup(q0, 7)
        self.assertEqual(
            automaton.run_noiseless(q0, [7]),
            [observation_bit(seed, q1, 1, params)],
        )

    def test_observation_is_step_domain_separated(self):
        params = LNATParams("obs-exp2", n=32, m=4, T=2, eta=0.0)
        seed = bytes(range(32))
        state = 123456
        bits = [observation_bit(seed, state, step, params) for step in range(1, 17)]
        self.assertGreater(len(set(bits)), 1)

    def test_input_expansion_is_profile_domain_separated(self):
        seed_a = bytes(32)
        _, a128 = generate_input_sequence(LNAT128, seed_a)
        _, a256 = generate_input_sequence(LNAT256, seed_a)
        self.assertNotEqual(a128[:16], a256[:16])

    def test_input_expansion_uses_full_16_bit_alphabet(self):
        seed_a = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
        _, values = generate_input_sequence(LNAT256, seed_a)
        self.assertTrue(any(value > 255 for value in values))

    def test_invalid_transition_input_rejected(self):
        automaton = LNATAutomaton(bytes(range(32)), LNAT128)
        with self.assertRaises(ValueError):
            automaton.table.lookup(0, 2**LNAT128.m)
        with self.assertRaises(ValueError):
            automaton.table.lookup(2**LNAT128.n, 0)

    def test_noise_is_reproducible_with_test_rng(self):
        params = LNATParams("noise-exp2", n=32, m=4, T=8, eta=0.5)
        automaton = LNATAutomaton(bytes(range(32)), params)
        q0 = automaton.derive_q0(b"nonce")
        inputs = list(range(8))
        self.assertEqual(
            automaton.run_noisy(q0, inputs, random.Random(7)),
            automaton.run_noisy(q0, inputs, random.Random(7)),
        )


if __name__ == "__main__":
    unittest.main()
