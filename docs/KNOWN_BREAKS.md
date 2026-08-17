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

The attack harness exactly recovers deliberately tiny seeds by exhaustive minimum-Hamming-distance search, including noisy multi-trace observations. This is expected and serves as a real attack baseline.

Do not extrapolate toy exhaustive-search results into a security level for larger profiles without a justified attack model.
