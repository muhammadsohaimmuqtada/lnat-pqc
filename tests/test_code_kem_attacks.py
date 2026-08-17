import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_kem_attacks import recover_code_kem_from_public_data
from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem import LNATCodeKEM0, LNATCodeKEMParams
from lnat_params import LNATParams


ATTACK_PARAMS = LNATCodeKEMParams(
    bridge=LNATCodeBridgeParams(
        code=CodePKEParams(
            n=64,
            k=32,
            secret_weight=2,
            encryption_error_weight=1,
            repetitions=96,
            zero_threshold=0.25,
        ),
        lnat=LNATParams(
            name="LNAT-code-kem-public-attack",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    ),
    encapsulated_seed_bytes=2,
    confirmation_tag_bytes=16,
)


class CodeKEMAttackTests(unittest.TestCase):
    def test_public_prange_attack_recovers_exact_session_key(self):
        kem = LNATCodeKEM0(ATTACK_PARAMS)
        pk, _ = kem.keygen(rng=random.Random(2001))
        ct, legitimate = kem.encap(pk, rng=random.Random(2002))
        recovered = recover_code_kem_from_public_data(
            pk,
            ct,
            rng=random.Random(2003),
            max_subsets=512,
        )
        self.assertEqual(recovered.session_key, legitimate)
        self.assertEqual(len(recovered.encapsulated_seed), 2)
        self.assertGreaterEqual(recovered.prange_subsets_sampled, 1)
        self.assertGreaterEqual(recovered.prange_invertible_subsets, 1)

    def test_attack_needs_no_lnat_secret_key(self):
        kem = LNATCodeKEM0(ATTACK_PARAMS)
        pk, _ = kem.keygen(rng=random.Random(2101))
        ct, legitimate = kem.encap(pk, rng=random.Random(2102))
        recovered = recover_code_kem_from_public_data(
            pk,
            ct,
            rng=random.Random(2103),
            max_subsets=512,
        )
        self.assertEqual(recovered.session_key, legitimate)


if __name__ == "__main__":
    unittest.main()
