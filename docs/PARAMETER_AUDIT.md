# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or the research LNAT code KEMs.

Parameter work is attack-first. Candidate sizes must be evaluated against the cheapest public attack model currently wired into the repository and against the conservative full-KEM correctness bound.

## 1. Direct sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are `C(n,w)` possible supports. The direct support-enumeration ceiling is therefore:

```text
log2(C(n,w)).
```

A 256-bit LNAT seed does not create 256 bits of public-key security when it maps into a smaller public witness space.

## 2. Executable reduced attack baselines

The repository keeps executable reduced-parameter attacks for mechanism validation:

- Prange-style information-set decoding;
- Lee-Brickell generalized ISD; and
- Stern collision/list ISD.

These attacks are valuable because they recover valid public syndrome witnesses on small instances. Their local reference cost models are useful for comparing mechanisms, but they are **not the active serious parameter-security estimator**.

Historical local-screen progression is retained for reproducibility:

```text
Prange/full-KEM only:            n=256,k=128,w=30
+ local Stern reference floor:  n=256,k=128,w=48
```

The maintained modern estimator later showed that `(256,128,w=48)` is only about `21.46` modeled attack bits under its strongest finite estimate. The old local `~64` Stern reference-operation count must therefore never be reported as a security level.

## 3. Maintained modern syndrome-decoding estimator

`src/code_sd_estimator.py` pins `cryptographic-estimators==2.1.1` and obtains finite estimates for modern syndrome-decoding algorithms including BJMM/May-Ozerov-family methods.

`src/code_modern_frontier.py` defines the serious effective attack screen as:

```text
effective_attack_bits = min(
    maintained_upstream_ISD_time_bits,
    log2(C(n,w)) direct support enumeration,
)
```

This prevents either the maintained estimator or a large LNAT seed from hiding an obviously cheaper public attack.

Estimator outputs remain model results, not proofs. A candidate crossing a requested numeric floor only survives the attack models currently evaluated.

## 4. Exact per-bit correctness model

For the Alekhnovich-style comparator, encryption of zero contains a dual-code word plus a fresh fixed-weight error. The dual-code component is orthogonal to the receiver's sparse witness, so the remaining inner-product error is determined by the parity of the intersection of two fixed-weight supports.

The repository computes that probability exactly and derives bit-0/bit-1 failure probabilities from binomial tails.

## 5. Full-KEM correctness composition

A small per-bit failure probability is not the KEM failure probability. For a uniformly random encapsulated bit,

```text
p_avg = (p0 + p1) / 2
```

and under the current independent-bit reference construction, the modeled `m`-bit seed failure probability is:

```text
1 - (1 - p_avg)^m.
```

The active correctness gate uses the more conservative union bound:

```text
m * max(p0, p1)
```

clamped to 1.

## 6. Current measured modern frontier

The modern scaling probe has already invalidated the dense n=256 candidate and moved the research frontier substantially upward.

Measured examples with the pinned estimator include:

```text
(256,128,w=28)    -> ~40.082 effective attack bits
(512,256,w=52)    -> ~64.839 modeled upstream attack bits
(1024,512,w=104)  -> ~115.373 modeled upstream attack bits
(1056,528,w=116)  -> ~127.669 effective attack bits; below a 128-bit screen
(1072,536,w=117)  -> ~128.615 effective attack bits; above a 128-bit screen
(1536,768,w=156)  -> ~164.819 modeled upstream attack bits
```

A focused measurement at `n=1064` is used to narrow the current 128-bit screening transition further. Until that measurement is fixed in CI, `(1072,536,w=117)` is only the smallest **measured passing point in the existing bracket**, not a standardized parameter set.

## 7. Tooling

```bash
python experiments/code_profile_audit.py
python experiments/lee_brickell_probe.py
python experiments/stern_probe.py
python experiments/upstream_isd_probe.py --n 256 --k 128 --weight 48
python experiments/modern_isd_scale_probe.py --point 1072:536:117
python experiments/modern_frontier_probe.py \
  --n 1072 --k 536 --weight 117 --attack-floor-bits 128
```

The modern-frontier commands require the pinned estimator extra:

```bash
python -m pip install -e ".[estimator]"
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious candidate until it has, at minimum:

1. explicit direct witness-space audit;
2. executable reduced syndrome-decoding attacks;
3. the pinned maintained modern estimator cross-check;
4. `min(modern ISD, support enumeration)` effective attack accounting;
5. conservative full-KEM correctness/failure analysis;
6. independent cryptanalysis; and
7. a clearly stated security assumption or reduction target.

Even satisfying all seven is a research milestone, not a security proof or deployment recommendation.
