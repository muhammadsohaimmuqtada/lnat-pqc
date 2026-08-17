# LNAT Security Status

## Current position

LNAT-EXP1 is an experimental learning/cryptanalysis target. **No cryptographic security level is claimed.** The archived KEM-v1 is completely broken by public recovery and must not be used.

The goal of this repository is now to produce falsifiable definitions, attacks, measurements, and negative results before proposing another cryptographic construction.

## What is actually implemented

The secret transition function is generated from a fixed-size seed using domain-separated HMAC-SHA256. The public observation at time `t` is the least-significant bit of the post-transition state, optionally flipped by independent Bernoulli noise.

This means security analysis must study the implemented seed-derived transition family and trace distribution. Arguments based only on the storage size or count of arbitrary finite-state transition tables are insufficient.

## KEM-v1 status

KEM-v1 is not IND-CPA secure. Its mask is the public `pk.Y`, so the encapsulated value is directly recoverable from public information. The repository contains a regression test and standalone attack that reproduce this break.

No Fujisaki-Okamoto transform or CCA wrapper can repair a base construction whose encapsulated secret is already public-recoverable.

## No parameter security mapping

The experiment profiles `LNAT-n128-exp1`, `LNAT-n192-exp1`, and `LNAT-n256-exp1` describe state sizes. They are not estimates of 128/192/256-bit security and are not mapped to NIST levels.

Any future security estimate must be supported by a defined attack game, concrete best-known attacks, parameter-dependent work factors, and independent review.

## Priority attack program

The most useful near-term work is adversarial:

1. exhaustive seed/state recovery at deliberately tiny parameters;
2. SAT/SMT encodings of transition and observation constraints;
3. statistical distinguishers against clearly defined null distributions;
4. correlation and state-prediction attacks;
5. multi-trace attacks with reused secret seeds and varying nonces/input seeds;
6. sample-complexity measurements;
7. analysis of whether the LSB observation creates exploitable bias or structure;
8. analysis of the seed-derived PRF family rather than an ideal arbitrary table.

## Requirements before KEM-v2

A KEM-v2 proposal should not begin until there is a precise asymmetric mechanism. At minimum, the design must explain why a public-key holder can form a ciphertext/shared secret that the private-key holder can recover while an observer possessing the same public key and ciphertext cannot.

Before any security claim, the repository should contain:

- a complete algorithm specification;
- explicit correctness and failure definitions;
- a formal security game;
- best-known attack implementations for small parameters;
- parameter rationale derived from those attacks;
- deterministic test vectors;
- independent cryptanalysis or review.

## Implementation hardening comes later

Constant-time code, optimized PRFs, embedded implementations, BCH/other coding, and performance benchmarking remain useful engineering topics, but they do not repair a broken construction. They should follow, not precede, evidence that the cryptographic design is meaningful.
