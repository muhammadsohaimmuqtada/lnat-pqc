import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_candidate_profiles import MODERN_128_SCREEN_V1


class CandidateProfileTests(unittest.TestCase):
    def test_modern128_screen_parameters_are_bound_exactly(self):
        profile = MODERN_128_SCREEN_V1
        self.assertEqual((profile.n, profile.k, profile.secret_weight), (1064, 532, 117))
        self.assertEqual(profile.encryption_error_weight, 1)
        self.assertEqual(profile.repetitions, 220)
        self.assertEqual(profile.cutoff_ones, 61)
        self.assertAlmostEqual(profile.threshold, 61 / 220)
        self.assertEqual(profile.encapsulated_seed_bits, 128)
        self.assertEqual(profile.estimator_algorithm, "MayOzerov")
        self.assertEqual(profile.estimator_version, "2.1.1")
        self.assertGreater(profile.measured_effective_attack_bits, 128.0)
        self.assertLessEqual(profile.conservative_kem_failure_bound, 1e-9)

    def test_modern128_screen_footprint_is_explicit(self):
        profile = MODERN_128_SCREEN_V1
        self.assertEqual(profile.word_bytes, 133)
        self.assertEqual(profile.generator_bytes, 70_756)
        self.assertEqual(profile.raw_public_code_bytes, 70_937)
        self.assertEqual(profile.public_context_bytes, 70_992)
        self.assertEqual(profile.ciphertext_body_bytes, 3_745_280)
        self.assertEqual(profile.ciphertext_bytes, 3_745_296)
        self.assertEqual(profile.private_seed_bytes, 32)

    def test_profile_builds_current_kem_parameter_object(self):
        profile = MODERN_128_SCREEN_V1
        params = profile.to_kem_params()
        code = params.bridge.code
        self.assertEqual(code.n, profile.n)
        self.assertEqual(code.k, profile.k)
        self.assertEqual(code.secret_weight, profile.secret_weight)
        self.assertEqual(code.encryption_error_weight, profile.encryption_error_weight)
        self.assertEqual(code.repetitions, profile.repetitions)
        self.assertAlmostEqual(code.zero_threshold, profile.threshold)
        self.assertEqual(params.encapsulated_seed_bytes, 16)
        self.assertEqual(params.confirmation_tag_bytes, 16)


if __name__ == "__main__":
    unittest.main()
