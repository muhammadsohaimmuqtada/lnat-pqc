# LNAT-EXP2 Primitive Specification

## Status

LNAT-EXP2 is the current standalone research primitive. It is specified for independent implementation, reproducible measurement, and cryptanalysis. It is **not** a standalone KEM and carries no claimed classical, quantum, NIST, IND-CPA, or IND-CCA security level.

The separate `LNAT-MLKEM768-HYBRID-v1` profile provides an operational KEM interface whose public-key security boundary is ML-KEM-768. See `HYBRID_KEM.md`.

## Parameters

A profile contains `n` (state width), `m` (input width), `T` (trace length), `eta` (noise probability), and `seed_size`. `kappa` remains only for archived KEM-v1 reproduction. Profile numbers describe engineering dimensions, not security strength.

## Domain separation

All HMAC-SHA256 PRF calls are prefixed by:

```text
LNAT-EXP2 | profile-name | purpose |
```

Purposes are `Q0`, `DELTA`, `OBS`, and `INPUT-SEQUENCE`.

## Secret transition family

```text
Delta_s(q, a) = Trunc_n(PRF_s(D_DELTA || Encode_n(q) || Encode_m(a)))
```

The implementation samples a seeded PRF-generated family, not an arbitrary transition table. Security reasoning must analyze the implemented seeded family rather than the cardinality of all possible automata.

## Initial state

```text
q_0 = Trunc_n(PRF_s(D_Q0 || N))
```

## Public input sequence

A 32-byte public seed expands deterministically into `T` values in `[0, 2^m)` under `D_INPUT-SEQUENCE`.

## Transition and observation

EXP2 is transition-first:

```text
q_t = Delta_s(q_{t-1}, a_t)
z_t = LSB(PRF_s(D_OBS || Encode_64(t) || Encode_n(q_t)))
```

EXP1 exposed `LSB(q_t)` directly. EXP2 replaces that fixed coordinate projection with a keyed observation PRF. This is a structural cleanup, not a hardness argument.

## Noise

```text
e_t ~ Bernoulli(eta)
y_t = z_t XOR e_t
```

## Reproducibility

The reference implementation includes a deterministic known-answer test. Any change to domain encoding, transition order, observation semantics, or bit packing requires a version change and new vectors.

## Research games

The primitive is evaluated through explicit distinguishing, seed-recovery, and prediction games in `GAMES.md`.

## Excluded construction: KEM-v1

The original KEM-v1 is excluded because its ciphertext mask was public and the encapsulated secret was recoverable from public data.
