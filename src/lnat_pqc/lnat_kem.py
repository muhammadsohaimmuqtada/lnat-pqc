# lnat_kem.py
# LNAT Key Encapsulation Mechanism
#
# Implements:
#   KeyGen  -> (public_key, private_key)
#   Encap   -> (ciphertext, session_key)
#   Decap   -> session_key
#
# Security target: IND-CPA demo only
# IND-CCA2 transform (e.g., Fujisaki-Okamoto) is not implemented
#
# NOTE: Reference implementation. Not for production use.

import os
import json
import hashlib
import secrets
from dataclasses import dataclass
from .lnat_params import LNATParams, LNAT128, ALL_PARAMS
from .lnat_core import LNATAutomaton, generate_seed, generate_input_sequence, prf


# ──────────────────────────────────────────────────────────────────────────────
# Key and ciphertext types
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class PublicKey:
    seed_A : bytes    # 32-byte seed to expand input sequence A
    nonce  : bytes    # 16-byte nonce used to derive q0
    Y      : list     # T-bit noisy output sequence (list of ints)
    params : LNATParams

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        Y_bytes = bits_to_bytes(self.Y)
        return (
            self.seed_A +
            self.nonce  +
            len(Y_bytes).to_bytes(4, "big") +
            Y_bytes
        )

    def size_bytes(self) -> int:
        return len(self.to_bytes())


@dataclass
class PrivateKey:
    seed   : bytes    # 32-byte master secret — this is the entire private key
    params : LNATParams

    def to_bytes(self) -> bytes:
        return self.seed

    def size_bytes(self) -> int:
        return len(self.seed)


@dataclass
class Ciphertext:
    ct_bits : list    # T-bit encrypted output

    def to_bytes(self) -> bytes:
        return bits_to_bytes(self.ct_bits)

    def size_bytes(self) -> int:
        return len(self.to_bytes())


# ──────────────────────────────────────────────────────────────────────────────
# Bit / byte utilities
# ──────────────────────────────────────────────────────────────────────────────

def bits_to_bytes(bits: list) -> bytes:
    """Pack a list of bits (0/1) into bytes."""
    # pad to multiple of 8
    padded = bits + [0] * ((-len(bits)) % 8)
    result = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | padded[i + j]
        result.append(byte)
    return bytes(result)


def bytes_to_bits(data: bytes, n_bits: int) -> list:
    """Unpack bytes into a list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits[:n_bits]


def xor_bits(a: list, b: list) -> list:
    """XOR two bit sequences."""
    assert len(a) == len(b), "Sequences must be same length"
    return [x ^ y for x, y in zip(a, b)]


# ──────────────────────────────────────────────────────────────────────────────
# Simple majority-vote error correction
# (placeholder for BCH — good enough for demo, not for production)
# ──────────────────────────────────────────────────────────────────────────────

def encode_with_repetition(bits: list, repeat: int = 3) -> list:
    """
    Simple repetition code.
    Each bit is repeated `repeat` times.
    Corrects up to floor(repeat/2) errors per bit.

    NOTE: BCH codes are the correct solution here.
    Repetition codes are used for clarity in this reference.
    """
    encoded = []
    for b in bits:
        encoded.extend([b] * repeat)
    return encoded


def decode_with_repetition(bits: list, repeat: int = 3) -> list:
    """Decode repetition code by majority vote."""
    decoded = []
    for i in range(0, len(bits), repeat):
        chunk = bits[i:i + repeat]
        # majority vote
        decoded.append(1 if sum(chunk) > repeat // 2 else 0)
    return decoded


# ──────────────────────────────────────────────────────────────────────────────
# Hash function (random oracle)
# ──────────────────────────────────────────────────────────────────────────────

def H(data: bytes, length: int = 32) -> bytes:
    """Hash function modeled as random oracle. Returns `length` bytes."""
    return hashlib.shake_256(data).digest(length)


# ──────────────────────────────────────────────────────────────────────────────
# LNAT-KEM
# ──────────────────────────────────────────────────────────────────────────────

class LNATKEM:
    """
    LNAT Key Encapsulation Mechanism.

    Usage:
        kem = LNATKEM(params)

        # Server setup (done once):
        pk, sk = kem.keygen()

        # Client connects:
        ct, K_client = kem.encap(pk)

        # Server decrypts:
        K_server = kem.decap(sk, pk, ct)

        assert K_client == K_server  # shared secret established
    """

    REPEAT = 5   # repetition code factor (replace with BCH in production)

    def __init__(self, params: LNATParams = LNAT128):
        self.params = params

    # ── KeyGen ────────────────────────────────────────────────────────────────

    def keygen(self) -> tuple:
        """
        KeyGen() -> (PublicKey, PrivateKey)

        Generates a fresh keypair.
        The private key is a 32-byte seed.
        The public key is (seed_A, nonce, Y).
        """
        params = self.params

        # 1. generate private seed
        seed = generate_seed(params)
        sk   = PrivateKey(seed=seed, params=params)

        # 2. create automaton from seed
        automaton = LNATAutomaton(seed, params)

        # 3. fresh nonce for this keypair → derive q0
        nonce = os.urandom(16)
        q0    = automaton.derive_q0(nonce)

        # 4. generate public input sequence
        seed_A, A = generate_input_sequence(params)

        # 5. run automaton with noise → public outputs Y
        rng    = secrets.SystemRandom()
        Y      = automaton.run_noisy(q0, A, rng=rng)

        pk = PublicKey(seed_A=seed_A, nonce=nonce, Y=Y, params=params)

        return pk, sk

    # ── Encap ─────────────────────────────────────────────────────────────────

    def encap(self, pk: PublicKey) -> tuple:
        """
        Encap(pk) -> (Ciphertext, session_key)

        Client-side. Generates a random session key r,
        encrypts it using the public key, returns
        (ciphertext, K) where K = H(r).
        """
        params = self.params

        # 1. generate random session key r (kappa bits)
        r_bits = [secrets.randbits(1) for _ in range(params.kappa)]

        # 2. encode r with repetition code for error correction
        r_encoded = encode_with_repetition(r_bits, self.REPEAT)

        # 3. expand public outputs Y to match encoded length
        #    repeat Y pattern to cover encoded length
        T_enc = len(r_encoded)
        Y_ext = (pk.Y * ((T_enc // len(pk.Y)) + 1))[:T_enc]

        # 4. ciphertext = r_encoded XOR Y_extended
        ct_bits = xor_bits(r_encoded, Y_ext)
        ct      = Ciphertext(ct_bits=ct_bits)

        # 5. session key = H(r)
        r_bytes = bits_to_bytes(r_bits)
        K       = H(r_bytes)

        return ct, K

    # ── Decap ─────────────────────────────────────────────────────────────────

    def decap(self,
              sk: PrivateKey,
              pk: PublicKey,
              ct: Ciphertext) -> bytes:
        """
        Decap(sk, pk, ct) -> session_key

        Server-side. Uses private seed to rerun the automaton,
        recovers Y, strips it from ciphertext, error-corrects r,
        returns K = H(r).
        """
        params = self.params

        # 1. rebuild automaton from private seed
        automaton = LNATAutomaton(sk.seed, params)

        # 2. recover q0 (same nonce is in the public key)
        q0 = automaton.derive_q0(pk.nonce)

        # 3. expand input sequence A from public seed_A
        _, A = generate_input_sequence(params, seed_A=pk.seed_A)

        # 4. run automaton NOISELESS — server knows the true Y
        Y_clean = automaton.run_noiseless(q0, A)

        # 5. extend Y_clean to match ciphertext length
        T_enc   = len(ct.ct_bits)
        Y_ext   = (Y_clean * ((T_enc // len(Y_clean)) + 1))[:T_enc]

        # 6. recover r_encoded (noisy due to original noise in pk.Y)
        r_encoded_noisy = xor_bits(ct.ct_bits, Y_ext)

        # 7. error-correct using repetition code
        r_bits = decode_with_repetition(r_encoded_noisy, self.REPEAT)
        r_bits = r_bits[:params.kappa]

        # 8. session key = H(r)
        r_bytes = bits_to_bytes(r_bits)
        K       = H(r_bytes)

        return K


# ──────────────────────────────────────────────────────────────────────────────
# Standalone demo
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    from .lnat_params import LNAT128

    print("LNAT-KEM Demo")
    print("=" * 50)

    kem = LNATKEM(LNAT128)

    # key generation
    print("\n[KeyGen]")
    pk, sk = kem.keygen()
    print(f"  Private key: {sk.to_bytes().hex()[:32]}... "
          f"({sk.size_bytes()} bytes)")
    print(f"  Public key size: {pk.size_bytes()} bytes")
    print(f"  Public Y (first 16 bits): {pk.Y[:16]}")

    # encapsulation
    print("\n[Encap — client side]")
    ct, K_client = kem.encap(pk)
    print(f"  Ciphertext size: {ct.size_bytes()} bytes")
    print(f"  Session key K: {K_client.hex()}")

    # decapsulation
    print("\n[Decap — server side]")
    K_server = kem.decap(sk, pk, ct)
    print(f"  Session key K: {K_server.hex()}")

    # verify
    print("\n[Result]")
    if K_client == K_server:
        print("  ✓ Keys match — KEM working correctly")
    else:
        print("  ✗ Keys DO NOT match — bug or decryption failure")

    print(f"\nParameter set: {LNAT128.name}")
    print(f"Classical security: {LNAT128.security_classical()} bits")
    print(f"Quantum security:   {LNAT128.security_quantum()} bits")
    print("\nSee README.md for open problems and known limitations.")
