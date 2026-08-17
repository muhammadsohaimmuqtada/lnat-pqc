import unittest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_kem import (
    BROKEN_SECURITY_NOTICE,
    LNATKEM,
    recover_session_key_from_public_data,
)
from lnat_params import LNATParams


NOISELESS = LNATParams(
    name="LNAT-kem-v1-test",
    n=32,
    m=4,
    T=128,
    eta=0.0,
    kappa=16,
)


class BrokenKEMV1Tests(unittest.TestCase):
    def test_instantiation_requires_explicit_acknowledgement(self):
        with self.assertRaisesRegex(RuntimeError, "cryptographically broken"):
            LNATKEM(NOISELESS)

    def test_historical_round_trip_still_reproduces(self):
        kem = LNATKEM(NOISELESS, allow_broken=True)
        pk, sk = kem.keygen()
        ct, expected = kem.encap(pk)
        self.assertEqual(expected, kem.decap(sk, pk, ct))

    def test_public_data_attack_recovers_session_key(self):
        kem = LNATKEM(NOISELESS, allow_broken=True)
        pk, _ = kem.keygen()
        ct, expected = kem.encap(pk)
        attacker_key = recover_session_key_from_public_data(pk, ct)
        self.assertEqual(expected, attacker_key)

    def test_security_notice_is_unambiguous(self):
        self.assertIn("public data", BROKEN_SECURITY_NOTICE)


if __name__ == "__main__":
    unittest.main()
