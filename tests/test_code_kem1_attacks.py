import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_kem1_attacks import recover_kem1_from_public_data
from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem1 import LNATCodeKEM1, LNATCodeKEM1Params
from lnat_params import LNATParams


ATTACK_PARAMS = LNATCodeKEM1Params(
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
            name="LNAT-code-kem1-public-attack",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    ),
    encapsulated_seed_bytes=4,
    channel_uses_per_byte=128,
    confirmation_tag_bytes=16,
)


class KEM1AttackTests(unittest.TestCase):
    def test_public_attack_recovers_exact_session_key(self):
        kem = LNATCodeKEM1(ATTACK_PARAMS)
        pk, _ = kem.keygen(rng=random.Random(4101))
        ct, legitimate = kem.encap(pk, rng=random.Random(4102))
        recovered = recover_kem1_from_public_data(
            pk,
            ct,
            rng=random.Random(4103),
            max_subsets=512,
        )
        self.assertEqual(recovered.session_key, legitimate)
        self.assertEqual(len(recovered.encapsulated_seed), 4)
        self.assertGreaterEqual(recovered.prange_subsets_sampled, 1)
        self.assertGreaterEqual(recovered.prange_invertible_subsets, 1)

    def test_attack_needs_no_lnat_secret(self):
        kem = LNATCodeKEM1(ATTACK_PARAMS)
        pk, _ = kem.keygen(rng=random.Random(4201))
        ct, legitimate = kem.encap(pk, rng=random.Random(4202))
        recovered = recover_kem1_from_public_data(
            pk,
            ct,
            rng=random.Random(4203),
            max_subsets=512,
        )
        self.assertEqual(recovered.session_key, legitimate)


if __name__ == "__main__":
    unittest.main()
