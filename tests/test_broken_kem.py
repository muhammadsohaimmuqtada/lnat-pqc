import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_kem import LNATKEM, recover_session_key_from_public_data
from lnat_params import LNATParams

NOISELESS = LNATParams("LNAT-kem-v1-test-exp2", n=32, m=4, T=128, eta=0.0, kappa=16)


class BrokenKEMV1Tests(unittest.TestCase):
    def test_gated(self):
        with self.assertRaisesRegex(RuntimeError, "cryptographically broken"):
            LNATKEM(NOISELESS)

    def test_negative_result_still_reproduces_after_exp2(self):
        kem = LNATKEM(NOISELESS, allow_broken=True)
        pk, sk = kem.keygen()
        ct, expected = kem.encap(pk)
        self.assertEqual(expected, kem.decap(sk, pk, ct))
        self.assertEqual(expected, recover_session_key_from_public_data(pk, ct))


if __name__ == "__main__":
    unittest.main()
