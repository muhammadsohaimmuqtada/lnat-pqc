import hashlib
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_cli import decap_files, encap_files, keygen_files, run, selftest
from lnat_hybrid_kem import (
    LNATMLKEM768,
    MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PRIVATE_SEED_BYTES,
    MLKEM768_PUBLIC_BYTES,
    MLKEM768_SHARED_SECRET_BYTES,
)
from lnat_params import DEFAULT_PARAMS


class FakeMLKEM768Backend:
    @staticmethod
    def _public(seed: bytes) -> bytes:
        return hashlib.shake_256(b"cli-fake-pk" + seed).digest(MLKEM768_PUBLIC_BYTES)

    def generate(self):
        seed = secrets.token_bytes(MLKEM768_PRIVATE_SEED_BYTES)
        return self._public(seed), seed

    def encapsulate(self, public_key: bytes):
        eph = secrets.token_bytes(32)
        padding = hashlib.shake_256(b"cli-fake-ct" + public_key + eph).digest(
            MLKEM768_CIPHERTEXT_BYTES - 32
        )
        ciphertext = eph + padding
        shared = hashlib.shake_256(b"cli-fake-ss" + public_key + eph).digest(
            MLKEM768_SHARED_SECRET_BYTES
        )
        return shared, ciphertext

    def decapsulate(self, private_seed: bytes, ciphertext: bytes):
        public = self._public(private_seed)
        return hashlib.shake_256(b"cli-fake-ss" + public + ciphertext[:32]).digest(
            MLKEM768_SHARED_SECRET_BYTES
        )

    def public_from_private_seed(self, private_seed: bytes):
        return self._public(private_seed)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.kem = LNATMLKEM768(DEFAULT_PARAMS, backend=FakeMLKEM768Backend())

    def test_file_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = root / "public.lnat"
            private = root / "private.lnat"
            ciphertext = root / "ciphertext.lnat"
            sender_key = root / "sender.key"
            receiver_key = root / "receiver.key"

            keygen_files(self.kem, public, private)
            encap_files(self.kem, public, ciphertext, sender_key)
            decap_files(self.kem, public, private, ciphertext, receiver_key)

            self.assertEqual(sender_key.read_bytes(), receiver_key.read_bytes())
            self.assertEqual(len(sender_key.read_bytes()), 32)

            if os.name == "posix":
                self.assertEqual(private.stat().st_mode & 0o777, 0o600)
                self.assertEqual(sender_key.stat().st_mode & 0o777, 0o600)
                self.assertEqual(receiver_key.stat().st_mode & 0o777, 0o600)

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public = root / "public.lnat"
            private = root / "private.lnat"
            keygen_files(self.kem, public, private)
            with self.assertRaises(FileExistsError):
                keygen_files(self.kem, public, private)
            keygen_files(self.kem, public, private, force=True)

    def test_rejects_path_aliasing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            same = Path(temp_dir) / "same.bin"
            with self.assertRaisesRegex(ValueError, "distinct"):
                keygen_files(self.kem, same, same)

    def test_selftest(self):
        self.assertTrue(selftest(self.kem))
        self.assertEqual(run(["selftest"], kem=self.kem), 0)


if __name__ == "__main__":
    unittest.main()
