import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_hybrid_kem import LNATMLKEM768


class RealMLKEMIntegrationTests(unittest.TestCase):
    def test_real_mlkem_round_trip(self):
        try:
            kem = LNATMLKEM768()
            pk, sk = kem.keygen()
        except RuntimeError as exc:
            if "cryptography>=47" in str(exc):
                self.skipTest(str(exc))
            raise
        ct, sender = kem.encap(pk)
        receiver = kem.decap(sk, pk, ct)
        self.assertEqual(sender, receiver)


if __name__ == "__main__":
    unittest.main()
