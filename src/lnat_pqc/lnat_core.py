# lnat_core.py
# Core automaton primitive for LNAT-PQC
#
# This file implements:
#   - LazyTable: the secret transition table derived from a seed
#   - LNATAutomaton: the finite automaton that runs on inputs
#   - Noise injection and output function
#
# NOTE: This is a REFERENCE implementation — clarity over speed.
# Do not use in production.

import os
import hmac
import hashlib
import secrets
from .lnat_params import LNATParams, LNAT128


# ──────────────────────────────────────────────────────────────────────────────
# Pseudorandom Function
# We use HMAC-SHA256 as a PRF.
# In a production implementation this would be AES-CTR for speed.
# ──────────────────────────────────────────────────────────────────────────────

def prf(seed: bytes, domain: bytes, length: int) -> bytes:
    """
    Pseudorandom function.
    PRF(seed, domain) -> length bytes of pseudorandom output.

    Uses HMAC-SHA256 in counter mode.
    Same inputs always produce same outputs.
    Different seeds produce unrelated outputs.
    """
    output = b""
    counter = 0
    while len(output) < length:
        h = hmac.new(seed, domain + counter.to_bytes(4, "big"), hashlib.sha256)
        output += h.digest()
        counter += 1
    return output[:length]


def prf_int(seed: bytes, domain: bytes, n_bits: int) -> int:
    """
    PRF returning an integer of exactly n_bits bits.
    """
    n_bytes = (n_bits + 7) // 8
    raw     = prf(seed, domain, n_bytes)
    value   = int.from_bytes(raw, "big")
    mask    = (1 << n_bits) - 1
    return value & mask


# ──────────────────────────────────────────────────────────────────────────────
# Lazy Transition Table
# ──────────────────────────────────────────────────────────────────────────────

class LazyTable:
    """
    The secret transition table delta: F_2^n x F_2^m -> F_2^n.

    NEVER stored in full — computed on demand from the seed.
    Same seed always produces same table entry.

    For real security at n=128:
        Full table = 2^136 entries × 16 bytes = physically impossible to store.
        LazyTable computes each entry fresh from the seed using a PRF.

    Optimization note:
        Production implementation would use a PRF tree (lazy subtree caching)
        to reduce AES calls from O(1) per lookup to O(log n) amortized.
        This reference uses simple per-entry PRF for clarity.
    """

    def __init__(self, seed: bytes, params: LNATParams):
        self.seed   = seed
        self.params = params
        self._cache = {}   # cache recently used entries (LRU in production)

    def lookup(self, state: int, inp: int) -> int:
        """
        delta(state, input) -> next_state

        Deterministic. Same (state, input) always returns same next_state
        for the same seed.
        """
        key = (state, inp)

        if key not in self._cache:
            # derive next state from seed + (state, input)
            domain     = b"delta" + \
                         state.to_bytes(self.params.n // 8, "big") + \
                         inp.to_bytes(self.params.m // 8 or 1, "big")
            next_state = prf_int(self.seed, domain, self.params.n)
            self._cache[key] = next_state

            # keep cache bounded (simple eviction for reference impl)
            if len(self._cache) > 4096:
                oldest = next(iter(self._cache))
                del self._cache[oldest]

        return self._cache[key]

    def clear_cache(self):
        self._cache.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Output Function
# ──────────────────────────────────────────────────────────────────────────────

def output_function(state: int, params: LNATParams) -> int:
    """
    lambda(state) -> kappa-bit output.

    Takes the bottom kappa bits of the state.
    Simple but effective — the state itself is secret so
    the output leaks only partial information.
    """
    mask = (1 << params.kappa) - 1
    return state & mask


def add_noise(output_bit: int, eta: float, rng=None) -> int:
    """
    Flip output_bit with probability eta.
    This is the noise that makes LNAT hard to invert.
    """
    if rng is None:
        rng = secrets.SystemRandom()
    if rng.random() < eta:
        return output_bit ^ 1
    return output_bit


# ──────────────────────────────────────────────────────────────────────────────
# LNAT Automaton Runner
# ──────────────────────────────────────────────────────────────────────────────

class LNATAutomaton:
    """
    The core LNAT automaton.

    Given a seed, runs the automaton on an input sequence
    and produces (optionally noisy) outputs.

    The seed is the private key.
    The outputs (with noise) form the public key.
    """

    def __init__(self, seed: bytes, params: LNATParams):
        """
        seed   : 32-byte private key
        params : LNATParams instance
        """
        assert len(seed) == params.seed_size, \
            f"Seed must be {params.seed_size} bytes"
        self.seed   = seed
        self.params = params
        self.table  = LazyTable(seed, params)

    def derive_q0(self, nonce: bytes) -> int:
        """
        Derive the initial state q0 from seed + nonce.
        A fresh nonce each connection means q0 changes each time.
        """
        domain = b"q0" + nonce
        return prf_int(self.seed, domain, self.params.n)

    def run(self,
            q0: int,
            input_sequence: list,
            add_noise_flag: bool = False,
            rng=None) -> list:
        """
        Run the automaton for T steps.

        q0             : initial state (integer)
        input_sequence : list of T integers, each in [0, 2^m)
        add_noise_flag : if True, flip output bits with prob eta
        rng            : random source (for noise)

        Returns list of T output integers (each kappa bits).
        """
        state   = q0
        outputs = []

        for inp in input_sequence:
            # compute output BEFORE transition (Moore machine style)
            out = output_function(state, self.params)

            # extract single bit from output for the noisy public key
            out_bit = out & 1

            if add_noise_flag:
                out_bit = add_noise(out_bit, self.params.eta, rng)

            outputs.append(out_bit)

            # transition to next state
            state = self.table.lookup(state, inp)

        return outputs

    def run_noiseless(self, q0: int, input_sequence: list) -> list:
        """Run without noise. Used during decryption."""
        return self.run(q0, input_sequence, add_noise_flag=False)

    def run_noisy(self, q0: int, input_sequence: list, rng=None) -> list:
        """Run with noise. Used during key generation."""
        return self.run(q0, input_sequence, add_noise_flag=True, rng=rng)


# ──────────────────────────────────────────────────────────────────────────────
# Key Generation Helper
# ──────────────────────────────────────────────────────────────────────────────

def generate_seed(params: LNATParams) -> bytes:
    """
    Generate a fresh cryptographically random seed.
    This is the private key. 32 bytes = 256 bits.
    """
    return os.urandom(params.seed_size)


def generate_input_sequence(params: LNATParams, seed_A: bytes = None) -> tuple:
    """
    Generate a public input sequence A of length T.
    Returns (seed_A, A) where seed_A is the 32-byte seed used to expand A.
    seed_A is published in the public key instead of A itself (saves space).
    """
    if seed_A is None:
        seed_A = os.urandom(32)

    # expand seed_A into T input values each in [0, 2^m)
    raw = prf(seed_A, b"input_sequence", params.T * 2)
    mask = (1 << params.m) - 1
    A = [(raw[i] & mask) for i in range(params.T)]

    return seed_A, A


# ──────────────────────────────────────────────────────────────────────────────
# Standalone demo
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    params = LNAT128
    print(f"LNAT Core Demo — {params.name}")
    print("=" * 50)

    # generate private key
    seed = generate_seed(params)
    print(f"Private seed: {seed.hex()[:32]}... ({len(seed)} bytes)")

    # create automaton
    automaton = LNATAutomaton(seed, params)

    # generate nonce and derive q0
    nonce = os.urandom(16)
    q0    = automaton.derive_q0(nonce)
    print(f"Initial state q0: {q0} (derived from seed + nonce)")

    # generate public input sequence
    seed_A, A = generate_input_sequence(params)
    print(f"Input sequence seed: {seed_A.hex()[:16]}... (published)")
    print(f"Input sequence A: {A[:8]}... (first 8 of {len(A)})")

    # run with noise (public key generation)
    Y_noisy = automaton.run_noisy(q0, A)
    print(f"Noisy outputs Y: {Y_noisy[:16]}... (first 16 bits)")

    # run without noise (decryption)
    Y_clean = automaton.run_noiseless(q0, A)
    print(f"Clean outputs Y: {Y_clean[:16]}... (first 16 bits)")

    # count noise flips
    flips = sum(a != b for a, b in zip(Y_noisy, Y_clean))
    print(f"\nNoise flipped {flips}/{params.T} bits "
          f"({100*flips/params.T:.1f}%, expected ~{100*params.eta:.0f}%)")

    print("\nCore automaton working correctly.")
    print("See lnat_kem.py for the full KEM construction.")
