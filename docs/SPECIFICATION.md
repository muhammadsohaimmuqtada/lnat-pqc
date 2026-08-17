# LNAT-EXP1 Primitive Specification

## Status

This document defines the current experimental primitive exactly enough for independent implementation and cryptanalysis. It does **not** define a secure KEM and it makes no classical, quantum, NIST, IND-CPA, or IND-CCA security claim.

## Parameters

An experiment profile contains:

- `n`: state size in bits;
- `m`: input-symbol width in bits;
- `T`: number of observed transitions;
- `eta`: independent observation-bit flip probability;
- `seed_size`: secret seed length in bytes.

The current implementation also retains `kappa` only for reproducing the archived KEM-v1 experiment.

## Domain separation

All HMAC-SHA256 PRF invocations are separated by:

```text
LNAT-EXP1 | parameter-profile-name | purpose |
```

where `purpose` is one of `Q0`, `DELTA`, or `INPUT-SEQUENCE`.

## Secret transition family

The implementation does not sample an arbitrary transition table from the set of all possible tables. Instead, a secret seed `s` selects one member of a PRF-generated family.

For state `q` and input `a`:

```text
Delta_s(q, a) = Trunc_n(PRF_s(D_DELTA || Encode_n(q) || Encode_m(a)))
```

The state and input encodings are fixed-width, big-endian encodings.

## Initial state

For public nonce `N`:

```text
q_0 = Trunc_n(PRF_s(D_Q0 || N))
```

## Public input sequence

A 32-byte public seed `seed_A` expands deterministically into `T` input symbols:

```text
A = Expand(seed_A, D_INPUT-SEQUENCE, T, m)
```

Each `a_t` is in `[0, 2^m)`.

## Transition and observation order

The reference process is **transition first, then observe**:

```text
q_t = Delta_s(q_{t-1}, a_t)
z_t = lambda(q_t)
```

The reference observation function is deliberately simple:

```text
lambda(q) = LSB(q)
```

This is a coordinate projection, not a random high-degree Boolean function.

## Noise

For each step, sample an independent noise bit:

```text
e_t ~ Bernoulli(eta)
y_t = z_t XOR e_t
```

The public noisy trace is `Y = (y_1, ..., y_T)`.

## Research problem

The repository currently studies, rather than assumes, questions such as:

- can an adversary distinguish noisy LNAT traces from an appropriate null distribution;
- can an adversary recover information about the secret seed, states, or transition behavior;
- how does attack complexity scale on small parameters;
- what structural information is leaked by the one-bit observation function;
- whether the PRF-generated transition family introduces exploitable structure at the trace level.

A precise game and advantage definition must accompany any future hardness claim.

## Excluded construction: KEM-v1

KEM-v1 is not part of this specification. It is archived because its ciphertext mask was public and therefore allowed complete public recovery of the encapsulated key. See `KNOWN_BREAKS.md`.
