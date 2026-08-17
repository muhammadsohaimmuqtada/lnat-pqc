# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or the research LNAT code KEMs.

Before a code-based research profile is even worth deeper cryptanalysis, necessary attack and correctness checks must be reported separately.

## 1. Full sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are `C(n,w)` possible supports. Therefore `log2(C(n,w))` is only a ceiling against basic full-support enumeration.

A 256-bit LNAT master seed cannot provide 256 bits of security if it deterministically maps into a much smaller public hidden-witness space.

## 2. Prange information-set baseline

For a binary `[n,k]` code and weight-`w` error, the basic Prange combinatorial model has expected information-set count

```text
C(n,w) / C(n-k,w)
```

when `w <= n-k`.

The repository reports `log2(expected information-set trials)` separately from full witness-space size. This is not a total operation count.

## 3. Stern collision/list baseline

The active frontier now also evaluates each candidate with the executable Stern-style collision model in `src/code_stern.py`.

That model explicitly accounts for:

- the useful information-set probability for `(p,l)`;
- left/right list sizes;
- expected projection collisions;
- a naive GF(2) elimination term;
- list/collision processing work; and
- list memory.

The resulting `stern-modeled-operation-bits` are **reference-model operation bits**, not a proven security level. They are deliberately kept separate from Prange trial bits because the units differ.

## 4. Exact per-bit correctness model

For the Alekhnovich-style comparator, an encryption of zero contains a dual-code word plus a fresh fixed-weight error. The dual-code component is orthogonal to the receiver's sparse witness, so the remaining inner-product error is controlled by the parity of the intersection of two fixed-weight supports.

The repository computes that probability exactly, then computes bit-0 and bit-1 failure probabilities with binomial tails.

## 5. Full-KEM correctness composition

A small per-bit failure probability is not the KEM failure probability.

For a uniformly random encapsulated bit,

```text
p_avg = (p0 + p1) / 2
```

and under the reference model's independent fresh encryption randomness, an `m`-bit seed has modeled failure probability

```text
1 - (1 - p_avg)^m.
```

The audit also reports the conservative union bound

```text
m * max(p0, p1)
```

clamped to 1. The active frontier uses this conservative bound as its correctness gate.

## 6. Attack-aware parameter frontier

`experiments/code_parameter_frontier.py` now requires all of these simultaneously:

1. a requested Prange expected-trial floor;
2. a requested Stern reference-operation floor;
3. an encapsulated-seed length; and
4. a requested conservative full-KEM failure ceiling.

Example:

```bash
python experiments/code_parameter_frontier.py \
  --n 256 --k 128 \
  --prange-trial-bits 32 \
  --stern-op-bits 64 \
  --error-weight 1 \
  --encapsulated-bits 128 \
  --kem-failure-ceiling 1e-9 \
  --max-repetitions 450
```

The deterministic research regression is now:

```text
n = 256
k = 128
secret weight = 48
Prange expected trial bits >= 32
Stern reference-operation bits >= 64
Stern best modeled p = 3
Stern best modeled l = 12
encapsulated seed = 128 bits
repetitions = 394
cutoff ones = 131
conservative full-KEM failure bound <= 1e-9
```

The previous `w=30`, 233-repetition point remains useful as a historical Prange/full-KEM correctness regression, but it does not pass the new 64-bit Stern reference-operation floor. This does **not** mean the new `w=48` point has 64 bits of cryptographic security. It only survives the attack models currently implemented in this repository.

## Tooling

```bash
python experiments/code_profile_audit.py
python experiments/code_parameter_frontier.py
python experiments/code_parameter_frontier.py --grid
python experiments/lee_brickell_probe.py
python experiments/stern_probe.py
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious candidate until it has, at minimum:

1. an explicit full witness-space audit;
2. executable Prange, Lee-Brickell, and Stern-style reduced attacks;
3. separate attack-cost metrics with explicit time/memory models;
4. an exact or conservative full-KEM correctness/failure analysis;
5. stronger Dumer/BJMM-style analysis before any security-level claim;
6. independent cryptanalysis; and
7. a clearly stated security assumption or reduction target.
