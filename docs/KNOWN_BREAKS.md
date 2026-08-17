# Known Breaks and Negative Results

## KEM-v1: complete public recovery

**Status:** complete break, reproducible.

Given public trace `Y` and ciphertext `ct`:

```text
ct = Encode(r) XOR Extend(Y)
```

an observer computes:

```text
Encode(r) = ct XOR Extend(Y)
r = Decode(Encode(r))
K = H(r)
```

The private seed is irrelevant. Regression: `attacks/public_recovery_v1.py` and `tests/test_broken_kem.py`.

## EXP1: fixed-coordinate observation

EXP1 observed `LSB(q_t)` directly. That was more structured than earlier documentation implied. EXP2 replaces the fixed coordinate with a keyed observation PRF. This is a removed avoidable structure, not a proof.

## Toy seed recovery

The attack harness exactly recovers deliberately tiny seeds by exhaustive minimum-Hamming-distance search, including noisy multi-trace observations. Branch-and-bound scoring reduces the number of trace-bit comparisons while preserving the exact exhaustive-search answer.

Do not extrapolate toy exhaustive-search results into a security level for larger profiles without a justified attack model.

## LNAT-CODE-BRIDGE-0 toy profiles: public decoding recovery

**Status:** expected complete break of the deliberately tiny bridge parameters; reproducible.

The bridge uses a 256-bit LNAT seed to deterministically select an exact-weight sparse code error `e`, but the public key exposes the random-code decoding instance `y = c + e`. An attacker does not need to recover the LNAT seed.

### Full sparse enumeration

An attacker can enumerate every public weight-`w` candidate and test the syndrome relation:

```text
for each weight-w candidate e':
    test whether y + e' belongs to the public code C
```

For the CI bridge profile `(n=64, w=2)`, this is only `C(64,2) = 2016` candidates, or about `10.98` bits of witness space.

### Prange-style information-set decoding

Full enumeration is not the best obvious attack. A basic Prange-style decoder samples `n-k` coordinates, solves the restricted public syndrome system, and accepts a solution of the advertised weight. The simple combinatorial model for `(n=64,k=32,w=2)` requires only

```text
C(64,2) / C(32,2) ≈ 4.06
```

expected information-set trials, before accounting for the polynomial linear-algebra work in each trial.

`src/code_attacks.py` implements this reduced-parameter decoder, and `attacks/bridge_sparse_witness_recovery.py` requires both public recovery methods to succeed and decrypt the test ciphertexts.

This result is deliberately recorded because **master-seed length is not a security metric** when the public hidden object can be attacked directly. Future bridge parameters must be evaluated against concrete decoding/ISD/BKW-style attack costs rather than against the LNAT seed size or full witness count alone.

## LNAT-CODE-KEM-0 toy profiles: complete public decapsulation after decoding

**Status:** expected complete break of the deliberately tiny KEM parameters; reproducible.

`LNAT-CODE-KEM-0` encrypts a random seed bit-by-bit using the same public random-code relation and then derives the session key from that seed, public context, ciphertext body, and a confirmation tag.

The confirmation tag catches wrong-key and tampering failures, but it does not protect the KEM if the public sparse code witness is decoded. Once Prange recovers the witness, an attacker can:

1. decrypt every encrypted seed bit;
2. reconstruct the encapsulated seed;
3. verify the public confirmation tag; and
4. derive the exact 32-byte session key.

No LNAT secret-seed recovery is required.

Regression: `attacks/code_kem_public_decapsulation.py` and `tests/test_code_kem_attacks.py`.

This negative result is intentional: the full KEM harness is useful for measuring correctness, size, transforms, and attacks, but it inherits the random-code decoding security boundary exactly as documented.
