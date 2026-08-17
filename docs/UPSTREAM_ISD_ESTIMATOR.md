# Modern syndrome-decoding estimator cross-check

## Purpose

The repository's executable Prange, Lee-Brickell, and Stern implementations are useful because reduced profiles can be attacked end-to-end and their mechanics are directly inspectable. They are not, however, the strongest known generic syndrome-decoding estimators.

For parameter screening, the repository therefore also supports a pinned cross-check against **Crypto-TII `cryptographic-estimators` 2.1.1** through `src/code_sd_estimator.py`.

The upstream binary Syndrome Decoding estimator includes finite-parameter models for algorithms including:

- Prange;
- Stern;
- Dumer;
- BJMM variants;
- Both-May;
- May-Ozerov;
- ball-collision variants.

This is intentionally an external reference rather than a copied local implementation. Reimplementing modern ISD formulas without reproducing their optimizer and cost conventions would create a second, easier-to-misread estimator.

## Reproducibility

The optional dependency is pinned:

```text
cryptographic-estimators==2.1.1
```

The bridge rejects a different installed version by default. This prevents CI numbers from silently changing when upstream cost models or optimization logic change.

Install and run:

```bash
python -m pip install -e ".[estimator]"
python experiments/upstream_isd_probe.py --n 256 --k 128 --weight 30 --top 8
```

The dedicated ISD workflow runs this cross-check separately from the dependency-free executable attack baselines.

## Interpretation

The upstream package reports bit-complexity and memory estimates under its own model. The repository's local Stern module reports a deliberately simple reference-operation count. Those are **not identical units**, so a numerical difference between them must not be described as a direct speedup.

The safe interpretation is:

1. executable local attacks establish that the attack mechanisms are real;
2. the pinned upstream estimator screens the same `(n,k,w)` instance against stronger published ISD families;
3. parameter candidates are rejected if a stronger modeled attack is too cheap;
4. no estimator output by itself proves a security level.

## Research references

- A. Becker, A. Joux, A. May, A. Meurer, *Decoding Random Binary Linear Codes in 2^(n/20): How 1+1=0 Improves Information Set Decoding*, EUROCRYPT 2012 / IACR ePrint 2012/026.
- Y. Hamdaoui, N. Sendrier, *A Non Asymptotic Analysis of Information Set Decoding*, IACR ePrint 2013/162.
- A. Esser, E. Bellini, *Syndrome Decoding Estimator*, PKC 2022.
- Crypto-TII, `CryptographicEstimators`, pinned here at PyPI release 2.1.1.
