# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator, `LNAT-CODE-BRIDGE-0`, or the research LNAT code KEMs.

Parameter work is attack-first. Candidate sizes must be evaluated against the cheapest public attack models currently wired into the repository, against a separate quantum-attack baseline, and against the conservative full-KEM correctness bound.

## Direct sparse-witness ceiling

For an exact-weight hidden witness of length `n` and weight `w`, direct support enumeration costs at most

```text
log2(C(n,w))
```

in the classical combinatorial search model. A large LNAT master seed cannot increase security beyond a smaller public witness space.

## Executable reduced attack baselines

The repository keeps executable reduced attacks for Prange, Lee-Brickell, and Stern syndrome decoding. They validate attack mechanisms by recovering valid public witnesses on small instances.

Their local cost models are useful for comparative research, but they are not the serious classical parameter-security estimator. In particular, the historical local Stern screen admitted `(256,128,w=48)` near a nominal 64 reference-operation-bit floor, while the maintained modern estimator measures that same point near only 21.46 modeled attack bits.

## Maintained modern classical syndrome-decoding screen

`src/code_sd_estimator.py` pins `cryptographic-estimators==2.1.1` and exposes finite modern syndrome-decoding estimates. `src/code_modern_frontier.py` defines the serious classical public attack screen as

```text
effective_classical_attack_bits = min(
    maintained_upstream_ISD_time_bits,
    log2(C(n,w)) direct support enumeration,
)
```

Estimator values are model results, not security proofs. Crossing a requested numeric floor means only that the candidate survives the classical public attack models currently evaluated by this repository.

## Quantum ISD baseline

The maintained estimator above is classical. A post-quantum project must not treat a classical 128-bit crossing as a 128-bit post-quantum result.

`src/code_quantum_isd.py` therefore adds a deliberately transparent finite baseline based on Grover/amplitude-amplification of Prange information-set search and of direct support enumeration. If a classical search count has exponent `b = log2(N)`, idealized Grover search uses `Theta(sqrt(N))` oracle iterations, so the query/iteration exponent is

```text
grover_iteration_bits = b / 2
```

The active quantum baseline is

```text
effective_quantum_search_bits = min(
    0.5 * prange_expected_trial_bits,
    0.5 * log2(C(n,w)),
)
```

These are **quantum search iteration exponents**, not gate counts. They omit the reversible linear-algebra oracle cost, quantum memory/circuit constraints, and constants. They are also not best-known-quantum-ISD estimates: Kachigar--Tillich (PQCrypto 2017, arXiv:1703.00263) and later work give quantum-walk improvements over simple Groverized Prange. Passing this baseline is therefore necessary but not sufficient.

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

## Classical 128-bit boundary and quantum rejection

The pinned modern classical estimator and direct support-enumeration ceiling give the following focused classical boundary at rate 1/2:

```text
(1056,528,w=116) -> ~127.669 effective classical bits: below 128
(1064,532,w=116) -> 127.612109 effective classical bits: below 128
(1064,532,w=117) -> 128.611921 effective classical bits: above 128
(1072,536,w=117) -> ~128.615 effective classical bits: above 128
```

For `(1064,532,w=117)` with encryption-error weight 1, a 128-bit encapsulated seed and conservative full-KEM failure ceiling `1e-9`, the current correctness model requires:

```text
repetitions = 220
cutoff ones = 61
conservative KEM failure bound = 8.44167402647e-10
```

However, the same `(1064,532,w=117)` geometry has

```text
Prange expected trial bits = 127.358779432322
Groverized Prange iteration bits = 63.679389716161
Groverized support-enumeration bits = 263.555987650400
```

so the transparent quantum-search bottleneck is Groverized Prange at about `63.68` iteration bits. Consequently `(1064,532,w=117)` remains a useful **classical-screen regression point**, but it is rejected as a post-quantum frontier candidate.

This does not mean the construction has exactly 63.68 bits of quantum gate security. The repository has not yet implemented a concrete reversible circuit/resource estimate or a finite best-known quantum-ISD estimator. It means the previous classical-only 128-bit screen was not adequate evidence for a PQC claim.

## Tooling

```bash
python -m pip install -e ".[estimator]"
python experiments/upstream_isd_probe.py --n 256 --k 128 --weight 48
python experiments/modern_isd_scale_probe.py --point 1064:532:116 --point 1064:532:117
python experiments/modern_frontier_probe.py --n 1064 --k 532 --weight 117 --attack-floor-bits 128
python experiments/quantum_isd_probe.py --n 1064 --k 532 --weight 117 --iteration-floor-bits 128 --expect reject
```

## Rule for future profiles

No future bridge/KEM profile should be presented as a serious post-quantum candidate until it has, at minimum:

1. direct sparse-support enumeration audit;
2. executable reduced syndrome-decoding attacks;
3. pinned maintained modern classical syndrome-decoding cross-check;
4. `min(modern ISD, support enumeration)` classical attack accounting;
5. a quantum ISD/search screen with the cost model and units stated explicitly;
6. conservative full-KEM correctness/failure analysis;
7. independent cryptanalysis; and
8. a clearly stated security assumption or reduction target.

Even satisfying all eight is a research milestone, not a security proof or deployment recommendation. The operational PQC path in this repository remains the standardized-ML-KEM-backed hybrid while the standalone research path is cryptanalyzed.
