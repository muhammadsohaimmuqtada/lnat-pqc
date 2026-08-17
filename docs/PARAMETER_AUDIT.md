# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or the research LNAT code KEMs.

Before a code-based research profile is even worth deeper cryptanalysis, necessary attack and correctness checks must be reported separately.

## 1. Full sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are `C(n,w)` possible supports. Therefore `log2(C(n,w))` is only a ceiling against basic full-support enumeration.

A 256-bit LNAT master seed cannot provide 256 bits of security if it deterministically maps into a much smaller public hidden-witness space.

## 2. Prange information-set baseline

For a binary `[n,k]` code and weight-`w` error, basic Prange has expected information-set count

```text
C(n,w) / C(n-k,w)
```

when `w <= n-k`. The repository reports `log2(expected information-set trials)` separately from total operation counts.

## 3. Stern collision/list baseline

`src/code_stern.py` implements a reduced Stern-style collision attack and a transparent time/list/memory model. Its `stern-modeled-operation-bits` are reference-model operation bits, not a proven security level.

## 4. Dumer enlarged-information-set baseline

`src/code_dumer.py` enlarges the information region from `k` to `k+l`, row-reduces the remaining `r-l` columns to partial systematic form, and collides two weight-`p/2` lists on the bottom `l` equations.

The active frontier now reports and can independently gate on `dumer-modeled-operation-bits`. This metric is kept separate from Prange trial bits and from the Stern metric even though Stern and Dumer share a similar reference cost accounting style.

On the current `(n=256,k=128,w=48)` regression, the repository model gives roughly:

```text
Stern: 64.115 reference-operation bits
Dumer: 63.969 reference-operation bits
```

so `w=48` no longer clears a 64-bit Dumer research floor.

## 5. Exact per-bit correctness model

For encryption of zero, the remaining inner-product error is controlled by the parity of the intersection of two fixed-weight supports. The repository computes that probability exactly and derives bit-0/bit-1 failure probabilities with binomial tails.

## 6. Full-KEM correctness composition

A small per-bit failure probability is not the KEM failure probability. For a uniformly random encapsulated bit,

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

## 7. Attack-aware parameter frontier

`experiments/code_parameter_frontier.py` now requires all requested filters simultaneously:

1. Prange expected-trial floor;
2. Stern reference-operation floor;
3. Dumer reference-operation floor;
4. encapsulated-seed length; and
5. conservative full-KEM failure ceiling.

Example:

```bash
python experiments/code_parameter_frontier.py \
  --n 256 --k 128 \
  --prange-trial-bits 32 \
  --stern-op-bits 64 \
  --dumer-op-bits 64 \
  --error-weight 1 \
  --encapsulated-bits 128 \
  --kem-failure-ceiling 1e-9 \
  --max-repetitions 450
```

The deterministic research regression becomes:

```text
n = 256
k = 128
secret weight = 49
Prange expected trial bits >= 32
Stern reference-operation bits >= 64
Dumer reference-operation bits >= 64
Dumer best modeled p = 6
Dumer best modeled l = 12
encapsulated seed = 128 bits
repetitions = 406
cutoff ones = 136
conservative full-KEM failure bound <= 1e-9
```

Historical progression is intentionally retained in tests:

```text
Prange/full-KEM only:  w=30, repetitions=233
+ Stern 64-bit model:  w=48, repetitions=394
+ Dumer 64-bit model:  w=49, repetitions=406
```

None of these lines is a cryptographic security-level claim. They show how the candidate frontier moves as stronger executable attack models are added.

## Tooling

```bash
python experiments/code_profile_audit.py
python experiments/code_parameter_frontier.py
python experiments/code_parameter_frontier.py --grid
python experiments/lee_brickell_probe.py
python experiments/stern_probe.py
python experiments/dumer_probe.py
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious candidate until it has, at minimum:

1. explicit full witness-space audit;
2. executable Prange, Lee-Brickell, Stern, and Dumer reduced attacks;
3. separate time/memory/list metrics;
4. conservative full-KEM correctness/failure analysis;
5. MMT/BJMM-style representation analysis before any security-level claim;
6. independent cryptanalysis; and
7. a clearly stated security assumption or reduction target.
