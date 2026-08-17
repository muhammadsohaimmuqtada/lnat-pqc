# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or `LNAT-CODE-KEM-0`.

Before a code-based research profile is even worth deeper cryptanalysis, several necessary checks must be reported separately.

## 1. Full sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are `C(n,w)` possible supports. Therefore

```text
log2(C(n,w))
```

is only a ceiling against basic full-support enumeration.

A 256-bit LNAT master seed cannot provide 256 bits of security if it deterministically maps into a public hidden witness whose support is much smaller.

## 2. Prange information-set decoding baseline

For a binary `[n,k]` code and weight-`w` error, the basic Prange combinatorial model has expected information-set count

```text
C(n,w) / C(n-k,w)
```

when `w <= n-k`.

The repository reports `log2(expected information-set trials)` separately from full witness-space size. This is **not** a total operation count: each trial contains linear algebra and stronger ISD variants can improve on basic Prange.

`src/code_attacks.py` includes an executable Prange-style decoder for reduced parameters.

## 3. Exact per-bit correctness model

For the Alekhnovich-style comparator, an encryption of zero contains a dual-code word plus a fresh fixed-weight error. The dual-code component is orthogonal to the receiver's sparse witness, so the remaining inner-product error is controlled by the parity of the intersection of the two fixed-weight supports.

The repository computes that probability exactly with the hypergeometric distribution, then computes bit-0 and bit-1 failure probabilities with binomial tails.

## 4. Full-KEM correctness composition

A small **per-bit** failure probability is not the KEM failure probability.

`LNAT-CODE-KEM-0` encrypts an entire random seed bit-by-bit. If the bit-0 and bit-1 decoding failure probabilities are `p0` and `p1`, then for a uniformly random encapsulated bit the modeled error probability is

```text
p_avg = (p0 + p1) / 2
```

and, under the reference model's independent fresh encryption randomness, an `m`-bit encapsulated seed has modeled failure probability

```text
1 - (1 - p_avg)^m.
```

The audit also reports the more conservative union bound

```text
m * max(p0, p1)
```

clamped to 1. The necessary frontier now uses this conservative bound as its correctness gate.

This matters materially. The old `(n=256,k=128,w=30)` regression with 183 repetitions achieved about `1e-9` **per bit**, but for a 128-bit encapsulated seed that composes to roughly `1.1e-7` modeled seed failure. It therefore does not meet a `1e-9` KEM-level target.

## 5. Necessary parameter frontier

`experiments/code_parameter_frontier.py` now combines:

1. a requested basic-Prange **trial floor**;
2. an encapsulated-seed length; and
3. a requested conservative **full-KEM failure ceiling**.

Example:

```bash
python experiments/code_parameter_frontier.py \
  --n 256 --k 128 \
  --prange-trial-bits 32 \
  --error-weight 1 \
  --encapsulated-bits 128 \
  --kem-failure-ceiling 1e-9
```

The current full-KEM regression point is:

```text
n = 256
k = 128
secret weight = 30
basic-Prange expected trial bits >= 32
encapsulated seed = 128 bits
repetitions = 233
cutoff ones = 66
conservative full-KEM failure bound <= 1e-9
```

The older 183-repetition point is retained only as a regression for the legacy per-bit calculation.

This means only that the 233-repetition point survives these **necessary filters**. It is not a 32-bit security claim, because the Prange number omits per-trial operation cost and stronger ISD methods may be cheaper. It is not a deployment recommendation.

## Tooling

```bash
python experiments/code_profile_audit.py
python experiments/code_parameter_frontier.py
python experiments/code_parameter_frontier.py --grid
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious candidate until it has, at minimum:

1. an explicit full witness-space audit;
2. basic Prange/ISD work estimates;
3. an exact or conservative **full-KEM** correctness/failure analysis;
4. executable attacks on reduced parameters;
5. stronger ISD/BKW-style analysis where applicable;
6. a clearly stated security assumption or reduction target.
