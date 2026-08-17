# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or the research LNAT code KEMs.

Parameter work is attack-first. Candidate sizes must be evaluated against the cheapest public attack model currently wired into the repository and against the conservative full-KEM correctness bound.

## Direct sparse-witness ceiling

For an exact-weight hidden witness of length `n` and weight `w`, direct support enumeration costs at most

```text
log2(C(n,w))
```

in the combinatorial search model. A large LNAT master seed cannot increase security beyond a smaller public witness space.

## Executable reduced attack baselines

The repository keeps executable reduced attacks for Prange, Lee-Brickell, and Stern syndrome decoding. They validate attack mechanisms by recovering valid public witnesses on small instances.

Their local cost models are useful for comparative research, but they are not the serious parameter-security estimator. In particular, the historical local Stern screen admitted `(256,128,w=48)` near a nominal 64 reference-operation-bit floor, while the maintained modern estimator measures that same point near only 21.46 modeled attack bits.

## Maintained modern syndrome-decoding screen

`src/code_sd_estimator.py` pins `cryptographic-estimators==2.1.1` and exposes finite modern syndrome-decoding estimates. `src/code_modern_frontier.py` defines the serious effective public attack screen as

```text
effective_attack_bits = min(
    maintained_upstream_ISD_time_bits,
    log2(C(n,w)) direct support enumeration,
)
```

Estimator values are model results, not security proofs. Crossing a requested numeric floor means only that the candidate survives the public attack models currently evaluated by this repository.

## Exact correctness and full-KEM failure

The per-bit zero error probability is derived exactly from the parity of the intersection of two fixed-weight supports. Bit-0 and bit-1 decision failures are computed with binomial tails.

For a uniformly random `m`-bit encapsulated seed, the reference model reports

```text
p_avg = (p0 + p1) / 2
modeled seed failure = 1 - (1 - p_avg)^m
```

and uses the more conservative bound

```text
min(1, m * max(p0,p1))
```

as the active correctness gate.

## Current measured 128-bit research screen

The pinned modern estimator and direct support-enumeration ceiling give the following focused boundary at rate 1/2:

```text
(1056,528,w=116) -> ~127.669 effective bits in the earlier sweep: below 128
(1064,532,w=116) -> 127.612109 effective bits: below 128
(1064,532,w=117) -> 128.611921 effective bits: above 128
(1072,536,w=117) -> ~128.615 effective bits: above 128
```

For `(1064,532,w=117)` with encryption-error weight 1, a 128-bit encapsulated seed and conservative full-KEM failure ceiling `1e-9`, the current correctness model requires:

```text
repetitions = 220
cutoff ones = 61
conservative KEM failure bound = 8.44167402647e-10
```

Direct support enumeration at this point is about `527.112` bits, so the pinned May-Ozerov estimate is the active modeled bottleneck.

`(1064,532,w=117)` is therefore the smallest **measured passing point in the current focused bracket**. It is not a standardized parameter set, not a 128-bit security claim, and not deployment-ready.

## Tooling

```bash
python -m pip install -e ".[estimator]"
python experiments/upstream_isd_probe.py --n 256 --k 128 --weight 48
python experiments/modern_isd_scale_probe.py --point 1064:532:116 --point 1064:532:117
python experiments/modern_frontier_probe.py --n 1064 --k 532 --weight 117 --attack-floor-bits 128
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious candidate until it has, at minimum:

1. direct sparse-support enumeration audit;
2. executable reduced syndrome-decoding attacks;
3. pinned maintained modern syndrome-decoding cross-check;
4. `min(modern ISD, support enumeration)` effective attack accounting;
5. conservative full-KEM correctness/failure analysis;
6. independent cryptanalysis; and
7. a clearly stated security assumption or reduction target.

Even satisfying all seven is a research milestone, not a security proof or deployment recommendation.
