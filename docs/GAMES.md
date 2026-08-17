# LNAT Cryptanalysis Games

Every future security statement must point to an explicit game and measured or proven advantage.

## Game D — trace distinguishing

1. Challenger samples a secret seed and public `(nonce, seed_A)`.
2. Challenger samples hidden bit `b`.
3. If `b=0`, return a noisy LNAT trace.
4. If `b=1`, return independent unbiased bits of the same length.
5. Adversary outputs `b'`.

Report:

```text
Adv_D = |Pr[b' = b] - 1/2|
```

Experiments must report sample count, profile, train/test separation, confidence interval, and code revision.

## Game R — seed recovery

The adversary receives one or more public `(nonce, seed_A, noisy_trace)` observations generated under one secret seed and outputs a candidate seed. Report exact recovery, Hamming score, candidates tested, runtime, and memory.

The repository includes exhaustive minimum-Hamming-distance recovery for deliberately tiny 8-bit and 16-bit seed spaces.

## Game P — next-bit prediction

Train only on designated training traces and predict held-out next bits. Compare against the best trivial majority baseline and report advantage with confidence intervals.

## Multi-trace variants

All games must also be tested when many traces share one secret seed but use distinct nonces and input seeds.

## Toy versus research profiles

Toy profiles intentionally reduce seed/state sizes so attacks finish. Results on them do not justify extrapolation to large profiles without an explicit complexity argument.
