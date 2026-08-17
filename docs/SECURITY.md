# LNAT Security Status

## Current status

There are three live research objects and one archived failure:

1. **LNAT-EXP2** — standalone experimental noisy-automaton primitive under active cryptanalysis. No public-key or post-quantum security level is claimed.
2. **LNAT-CODE research line** — random-code asymmetric comparator/KEM experiments. The public-key hardness boundary is syndrome decoding, not a new LNAT assumption. Current large points are research screens only and are not post-quantum parameter recommendations.
3. **LNAT-MLKEM768-HYBRID-v1** — operational research KEM integration whose public-key security boundary is ML-KEM-768; LNAT is deterministic post-processing.
4. **LNAT KEM-v1** — broken and retained as a reproducible negative result.

## Why KEM-v1 failed

KEM-v1 XORed an encoded random secret with `pk.Y`. Because `pk.Y` was public, an observer could perform the same XOR, decode the secret, and compute the session key. No automaton inversion was needed.

`attacks/public_recovery_v1.py` must continue to reproduce this break in CI.

## EXP2 design correction

EXP1 published `LSB(q_t)`, a fixed state coordinate. EXP2 uses a keyed, step-separated observation bit derived through HMAC-SHA256. This removes that specific coordinate projection but does not establish hardness.

## Random-code research boundary

`LNAT-CODE-BRIDGE-0` does not make the secret-seeded LNAT automaton publicly evaluable. Instead it derives a sparse secret witness for an Alekhnovich-style random-code public relation. Consequently the relevant public attack problem is random binary syndrome decoding.

The repository maintains two separate screens:

- a **classical** finite-parameter screen using pinned `cryptographic-estimators==2.1.1` plus direct support enumeration; and
- a **quantum-search baseline** that applies Grover/amplitude-amplification to Prange search and direct support enumeration.

The classical `(1064,532,w=117)` regression point reaches about `128.612` modeled classical attack bits under the pinned estimator, but its transparent Groverized-Prange search exponent is only about `63.679` oracle iterations in log2 units. It is therefore rejected as a post-quantum parameter candidate.

That `63.679` number is not a claim of exact quantum gate security. The baseline omits reversible-oracle cost, circuit width/depth, quantum-memory restrictions, and stronger quantum ISD algorithms. A future random-code candidate needs a finite best-known quantum attack/resource analysis before any post-quantum security discussion.

See `docs/PARAMETER_AUDIT.md` for the exact models and regression values.

## Claims deliberately not made

The repository does not claim standalone LNAT or the random-code research line has:

- `n` bits of classical security;
- `n/2` bits of quantum security;
- a 128-bit post-quantum security level merely because a classical estimator crosses 128;
- NIST security levels;
- IND-CPA or IND-CCA security;
- a reduction to LPN, LWE, syndrome decoding, MQ, or another accepted problem for standalone LNAT;
- security from the size of a hypothetical full transition table.

## Required evidence before standalone KEM work

A future standalone LNAT KEM needs at minimum:

1. a precise public-key trapdoor/asymmetric relation;
2. an explicit security game;
3. concrete attacks on small parameters;
4. no direct public-data recovery path;
5. parameter selection based on attack cost rather than state width alone;
6. separate classical and quantum attack accounting;
7. failure-probability analysis;
8. malformed-ciphertext/chosen-ciphertext analysis;
9. independent cryptanalysis.

For any random-code comparator promoted beyond a toy experiment, the quantum analysis must include stronger information-set-decoding attacks rather than stopping at Groverized Prange.

## Side channels

The Python implementation is not constant-time and is not production code.
