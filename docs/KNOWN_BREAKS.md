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

## LNAT-CODE-BRIDGE-0 toy profiles: public sparse-witness recovery

**Status:** expected complete break of the deliberately tiny bridge parameters; reproducible.

The bridge uses a 256-bit LNAT seed to deterministically select an exact-weight sparse code error `e`, but the public key exposes the random-code decoding instance `y = c + e`. An attacker does not need to recover the LNAT seed. They can enumerate all public weight-`w` candidates and test the public syndrome relation:

```text
for each weight-w candidate e':
    test whether y + e' belongs to the public code C
```

For the CI bridge profile `(n=64, w=2)`, this is only `C(64,2) = 2016` candidates, or about `10.98` bits of witness space. Once `e` is recovered, the attacker can decrypt the toy code-PKE ciphertexts directly.

Regression: `attacks/bridge_sparse_witness_recovery.py` and `tests/test_code_attacks.py`.

This result is deliberately recorded because **master-seed length is not a security metric** when the public hidden object lives in a much smaller support. Future bridge parameters must be evaluated against concrete decoding/ISD/BKW-style attack costs rather than against the LNAT seed size.
