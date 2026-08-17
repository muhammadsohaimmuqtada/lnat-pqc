import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_core import LNATAutomaton, bits_to_bytes, generate_input_sequence
from lnat_params import LNATParams


class KnownAnswerTests(unittest.TestCase):
    def test_exp2_reference_vector(self):
        params = LNATParams("LNAT-KAT-exp2", n=32, m=4, T=16, eta=0.0, kappa=16)
        seed = bytes(range(32))
        nonce = bytes(range(16))
        seed_a = bytes(range(32, 64))
        automaton = LNATAutomaton(seed, params)
        q0 = automaton.derive_q0(nonce)
        _, inputs = generate_input_sequence(params, seed_a)
        trace = automaton.run_noiseless(q0, inputs)

        self.assertEqual(q0, 0xB9F5E44F)
        self.assertEqual(inputs, [0, 2, 1, 9, 15, 10, 15, 2, 7, 8, 10, 10, 14, 14, 2, 15])
        self.assertEqual(bits_to_bytes(trace).hex(), "cafe")
        self.assertEqual(
            hashlib.sha256(bits_to_bytes(trace)).hexdigest(),
            "03346f0e7990de2423a3bca5335bf92cdc0bd14bef2206b87c63f18a1e996c52",
        )


if __name__ == "__main__":
    unittest.main()
