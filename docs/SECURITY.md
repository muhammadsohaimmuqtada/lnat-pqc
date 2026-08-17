# LNAT Security Status

## Current status

There are two live objects and one archived failure:

1. **LNAT-EXP2** — standalone experimental noisy-automaton primitive under active cryptanalysis. No public-key or post-quantum security level is claimed.
2. **LNAT-MLKEM768-HYBRID-v1** — operational research KEM integration whose public-key security boundary is ML-KEM-768; LNAT is deterministic post-processing.
3. **LNAT KEM-v1** — broken and retained as a reproducible negative result.

## Why KEM-v1 failed

KEM-v1 XORed an encoded random secret with `pk.Y`. Because `pk.Y` was public, an observer could perform the same XOR, decode the secret, and compute the session key. No automaton inversion was needed.

`attacks/public_recovery_v1.py` must continue to reproduce this break in CI.

## EXP2 design correction

EXP1 published `LSB(q_t)`, a fixed state coordinate. EXP2 uses a keyed, step-separated observation bit derived through HMAC-SHA256. This removes that specific coordinate projection but does not establish hardness.

## Claims deliberately not made

The repository does not claim standalone LNAT has:

- `n` bits of classical security;
- `n/2` bits of quantum security;
- NIST security levels;
- IND-CPA or IND-CCA security;
- a reduction to LPN, LWE, MQ, or another accepted problem;
- security from the size of a hypothetical full transition table.

## Required evidence before standalone KEM work

A future standalone LNAT KEM needs at minimum:

1. a precise public-key trapdoor/asymmetric relation;
2. an explicit security game;
3. concrete attacks on small parameters;
4. no direct public-data recovery path;
5. parameter selection based on attack cost rather than state width alone;
6. failure-probability analysis;
7. malformed-ciphertext/chosen-ciphertext analysis;
8. independent cryptanalysis.

## Side channels

The Python implementation is not constant-time and is not production code.
