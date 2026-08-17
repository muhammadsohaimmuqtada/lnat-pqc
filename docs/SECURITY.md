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

The repository maintains separate screens for different evidence classes:

- a **classical** finite-parameter screen using pinned `cryptographic-estimators==2.1.1` plus direct support enumeration;
- a **quantum-search rejection baseline** that applies Grover/amplitude-amplification to Prange search and direct support enumeration;
- a **paper-grounded quantum Prange resource surface** that exposes logical-qubit counts and the published asymptotic depth scale; and
- the conservative full-KEM correctness/failure bound.

`src/code_post_quantum_frontier.py` requires the classical, quantum-search, and correctness gates simultaneously while keeping their units separate. `src/code_quantum_prange_resources.py` then exposes the physical-resource assumptions behind the currently implemented quantum Prange path.

The older `(1064,532,w=117)` regression point reaches about `128.612` modeled classical attack bits under the pinned estimator, but its transparent Groverized-Prange search exponent is only about `63.679` iteration bits. It is therefore rejected as a post-quantum parameter candidate.

A later focused rate-1/2 sweep held the witness weight fixed at `w=230` and located an adjacent implemented-screen boundary:

```text
(1692,846,w=230)
  BJMMplus classical bits       127.865290976502
  Groverized-Prange iter. bits  128.043027439769
  KEM failure bound             9.35699517868e-10
  result                        REJECT

(1694,847,w=230)
  BJMMplus classical bits       128.408410067763
  Groverized-Prange iter. bits  128.025066962080
  KEM failure bound             8.82707240635e-10
  result                        PASS (implemented screen only)
```

Thus `(1694,847,w=230)` is only the smallest measured passing point in that focused fixed-weight, even-`n` bracket. It is **not** a post-quantum security level, a global parameter optimum, or a deployment recommendation.

## Concrete Prange resource surface

The repository now instantiates the circuit-resource formulas from Esser et al., *An Optimized Quantum Implementation of ISD on Scalable Quantum Resources* (ePrint 2021/1608 / arXiv:2112.06157), with provenance pinned to the authors' supplementary `qiboteam/qISD` implementation at commit `456b3c60987e426a18d4ed4e5ebeaee3d2570958`.

For `(1694,847,w=230)` the model reports:

```text
Prange expected-trial bits                256.050133924
idealized Grover iteration bits            127.676563092
width-optimized logical qubits             721,643
depth-oriented full logical qubits         1,438,205
Table-2 width-optimized depth-scale bits   163.278287166
```

The qubit counts are closed-form logical-qubit counts from the paper. The depth-scale value is **not** an exact gate depth: Table 2 states it using big-O notation, so multiplicative constants and concrete gate decomposition costs are hidden. The qISD supplementary simulator is intended for small circuits and is not treated as a way to simulate a 700k-qubit attack.

These resource figures strengthen the accounting around the current Prange attack, but they do not rescue the parameter point or establish a PQ security level. Stronger quantum ISD algorithms remain outside the finite model.

See `docs/PARAMETER_AUDIT.md` for the attack/correctness boundary and `docs/QUANTUM_RESOURCES.md` for the circuit-resource units and provenance.

## Claims deliberately not made

The repository does not claim standalone LNAT or the random-code research line has:

- `n` bits of classical security;
- `n/2` bits of quantum security;
- a 128-bit post-quantum security level merely because the implemented classical and Groverized-search screens both cross 128;
- an exact quantum gate-security level derived from a big-O circuit-depth expression;
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

For any random-code comparator promoted beyond a toy experiment, the quantum analysis must include stronger information-set-decoding attacks rather than stopping at Groverized Prange, and any concrete-resource claim must distinguish logical qubits, oracle iterations, gate depth, qRAM assumptions, and fault-tolerant overhead.

## Side channels

The Python implementation is not constant-time and is not production code.
