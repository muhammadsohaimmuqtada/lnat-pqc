# test_kem.py
# Correctness tests for LNAT-KEM
#
# Run with: python tests/test_kem.py
# All tests should pass before any commit.

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from lnat_params import LNAT128, LNAT192, LNAT256, ALL_PARAMS
from lnat_kem    import LNATKEM

PASS = "✓"
FAIL = "✗"
results = []

def test(name, condition):
    status = PASS if condition else FAIL
    results.append((name, condition))
    print(f"  {status}  {name}")
    return condition


# ──────────────────────────────────────────────────────────────────────────────
# Test 1 — Basic correctness (keys match after round trip)
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 1 — Basic round-trip correctness (LNAT-128)")
kem = LNATKEM(LNAT128)
pk, sk = kem.keygen()
ct, K_enc = kem.encap(pk)
K_dec = kem.decap(sk, pk, ct)
test("Encap and Decap produce same session key", K_enc == K_dec)
test("Session key is 32 bytes", len(K_enc) == 32)
test("Ciphertext is non-empty", len(ct.ct_bits) > 0)
test("Public key has Y of length T", len(pk.Y) == LNAT128.T)


# ──────────────────────────────────────────────────────────────────────────────
# Test 2 — Different keypairs produce different session keys
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 2 — Independent keypairs are independent")
kem = LNATKEM(LNAT128)
pk1, sk1 = kem.keygen()
pk2, sk2 = kem.keygen()
ct1, K1 = kem.encap(pk1)
ct2, K2 = kem.encap(pk2)
K1_dec = kem.decap(sk1, pk1, ct1)
K2_dec = kem.decap(sk2, pk2, ct2)
test("KEM 1 round trip correct", K1 == K1_dec)
test("KEM 2 round trip correct", K2 == K2_dec)
test("Two different keypairs produce different session keys", K1 != K2)
test("Private keys are different", sk1.seed != sk2.seed)
test("Public keys have different Y", pk1.Y != pk2.Y)


# ──────────────────────────────────────────────────────────────────────────────
# Test 3 — Wrong private key cannot decapsulate
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 3 — Wrong private key fails")
kem = LNATKEM(LNAT128)
pk1, sk1 = kem.keygen()
pk2, sk2 = kem.keygen()
ct, K_correct = kem.encap(pk1)
K_wrong = kem.decap(sk2, pk1, ct)   # wrong sk
test("Wrong private key does not recover correct key", K_correct != K_wrong)


# ──────────────────────────────────────────────────────────────────────────────
# Test 4 — Multiple encapsulations to same public key give different session keys
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 4 — Same public key, multiple sessions")
kem = LNATKEM(LNAT128)
pk, sk = kem.keygen()
sessions = set()
for _ in range(10):
    ct, K = kem.encap(pk)
    sessions.add(K)
test("10 encapsulations produce 10 unique session keys", len(sessions) == 10)


# ──────────────────────────────────────────────────────────────────────────────
# Test 5 — Private key is exactly seed_size bytes
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 5 — Key sizes")
kem = LNATKEM(LNAT128)
pk, sk = kem.keygen()
test(f"Private key is {LNAT128.seed_size} bytes",
     sk.size_bytes() == LNAT128.seed_size)
test("Public key is larger than private key",
     pk.size_bytes() > sk.size_bytes())


# ──────────────────────────────────────────────────────────────────────────────
# Test 6 — Determinism: same seed + same nonce = same public key
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 6 — Determinism")
import os
from lnat_core import LNATAutomaton, generate_input_sequence
from lnat_params import LNAT128

seed   = os.urandom(32)
nonce  = os.urandom(16)
seed_A = os.urandom(32)

aut1 = LNATAutomaton(seed, LNAT128)
aut2 = LNATAutomaton(seed, LNAT128)
q0_a = aut1.derive_q0(nonce)
q0_b = aut2.derive_q0(nonce)
_, A = generate_input_sequence(LNAT128, seed_A=seed_A)
Y1 = aut1.run_noiseless(q0_a, A)
Y2 = aut2.run_noiseless(q0_b, A)
test("Same seed + nonce always produces same Y (noiseless)", Y1 == Y2)


# ──────────────────────────────────────────────────────────────────────────────
# Test 7 — Noise rate is approximately eta
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 7 — Noise rate")
import secrets as sec
from lnat_core import LNATAutomaton, generate_input_sequence

seed  = os.urandom(32)
nonce = os.urandom(16)
aut   = LNATAutomaton(seed, LNAT128)
q0    = aut.derive_q0(nonce)
_, A  = generate_input_sequence(LNAT128)

Y_clean = aut.run_noiseless(q0, A)
Y_noisy = aut.run_noisy(q0, A, rng=sec.SystemRandom())

flips      = sum(a != b for a, b in zip(Y_clean, Y_noisy))
actual_eta = flips / len(Y_clean)
expected   = LNAT128.eta

test(
    f"Noise rate ~{expected:.0%} (got {actual_eta:.1%}, tolerance ±5%)",
    abs(actual_eta - expected) < 0.05
)


# ──────────────────────────────────────────────────────────────────────────────
# Test 8 — Round-trip correctness across LNAT-128/192/256
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 8 — Round-trip correctness for all parameter sets")
for params in [LNAT128, LNAT192, LNAT256]:
    kem = LNATKEM(params)
    pk, sk = kem.keygen()
    ct, K_enc = kem.encap(pk)
    K_dec = kem.decap(sk, pk, ct)
    test(f"{params.name}: Encap/Decap session key match", K_enc == K_dec)
    test(f"{params.name}: Public key size estimator matches serialization",
         pk.size_bytes() == params.public_key_size_bytes())
    test(f"{params.name}: Ciphertext size estimator matches serialization",
         ct.size_bytes() == params.ciphertext_size_bytes())


# ──────────────────────────────────────────────────────────────────────────────
# Test 9 — Regression: LNAT-256 input generation uses full m=16 chunks
# ──────────────────────────────────────────────────────────────────────────────

print("\nTest 9 — LNAT-256 input-sequence regression (m=16)")
from lnat_core import generate_input_sequence, prf

seed_A = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
_, A256 = generate_input_sequence(LNAT256, seed_A=seed_A)
raw = prf(seed_A, b"input_sequence", LNAT256.T * 2)
expected_prefix = [int.from_bytes(raw[i * 2:(i + 1) * 2], "big")
                   for i in range(32)]

test("LNAT-256 values are in [0, 2^16)", all(0 <= x < (1 << 16) for x in A256))
test("LNAT-256 includes values above 255", any(x > 255 for x in A256))
test("LNAT-256 first values use 2-byte chunks", A256[:32] == expected_prefix)


# ──────────────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────────────

passed = sum(1 for _, r in results if r)
total  = len(results)
print(f"\n{'='*50}")
print(f"Results: {passed}/{total} tests passed")

if passed == total:
    print("All tests passed.")
else:
    print("SOME TESTS FAILED. See above.")
    sys.exit(1)
