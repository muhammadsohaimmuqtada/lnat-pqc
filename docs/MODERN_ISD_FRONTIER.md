# Modern-ISD research frontier

## Status

The old automatic Stern-aware frontier is retained for reproducibility, but it is **not the active parameter authority**.

A maintained finite-parameter syndrome-decoding estimator showed that the old `(n=256,k=128,w=48)` point, despite clearing the repository's local Stern reference-operation floor, has only about `21.46` bits of modeled attack work in the pinned modern estimator.

The active research screen therefore evaluates explicit parameter points with `src/code_modern_frontier.py`.

## Gates

A candidate must satisfy all of the following:

1. full-KEM correctness under the existing conservative union-bound model;
2. any requested cheap Prange prefilter;
3. direct weight-`w` support enumeration;
4. the pinned `cryptographic-estimators==2.1.1` syndrome-decoding estimate;
5. `min(support enumeration, maintained ISD estimate)` must clear the requested modeled-work floor.

No monotonic relationship between witness weight and attack cost is assumed.

## Measured 128-bit screening boundary

For the focused rate-1/2 lower-weight sweep performed on 2026-08-17:

| point `(n,k,w)` | fastest maintained attack | modeled attack bits | full-KEM repetitions | result |
| --- | --- | ---: | ---: | --- |
| `(1024,512,112)` | May-Ozerov | ~123.71 | 220 | reject |
| `(1056,528,116)` | May-Ozerov | ~127.67 | 220 | reject |
| `(1072,536,117)` | May-Ozerov | ~128.61 | 220 | first measured crossing |
| `(1088,544,119)` | May-Ozerov | ~130.54 | 220 | clears screen |

For `(1072,536,117)`, the conservative full-KEM failure bound at the selected decision rule is approximately `6.996e-10`, below the `1e-9` research ceiling.

The direct support space is much larger than the maintained ISD estimate at this point, so May-Ozerov is the effective attack in this screen.

## Critical interpretation

`(1072,536,117)` is the **active research screening candidate**, not a secure or deployable parameter set.

The number `128.61` means only that the pinned estimator's current cost model reports roughly that logarithmic work factor for its cheapest modeled attack among the included algorithms. It is **not**:

- a proof of 128-bit security;
- a NIST security category;
- an IND-CPA or IND-CCA reduction;
- evidence against future or specialized decoding attacks;
- permission to deploy `LNAT-CODE-KEM-1`.

The operational PQC path remains `LNAT-MLKEM768-HYBRID-v1`, whose public-key security boundary is ML-KEM-768.

## Reproduce

```bash
python -m pip install -e ".[estimator]"
python experiments/modern_frontier_probe.py
```

The probe must reject the measured 1056 neighbor and accept the measured 1072 research point before this frontier is considered internally consistent.
