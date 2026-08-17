# Information-set decoding baselines

## Status

The public random-code relation used by the research bridge/KEM must be evaluated as a syndrome-decoding target. No LNAT master-seed length is used as a substitute for decoding work.

The repository now has four executable information-set decoding baselines:

1. **Prange-style decoding** in `src/code_attacks.py`;
2. **Lee-Brickell-style generalized ISD** in `src/code_isd.py`;
3. **Stern-style collision/list ISD** in `src/code_stern.py`;
4. **Dumer-style enlarged-information-set collision ISD** in `src/code_dumer.py`.

These are attack baselines, not security proofs.

## Lee-Brickell generalization

Let the public code have length `n`, dimension `k`, parity dimension `r=n-k`, and hidden error weight `w`.

Choose an information set `I` of size `k` and its complement `J` of size `r`. If the parity-check submatrix on `J` is invertible, guess that exactly `p` error positions lie in `I`, solve the remaining square system on `J`, and accept when the solved part has weight `w-p`.

Ignoring invertibility, the exact combinatorial event probability is:

```text
C(k,p) * C(n-k,w-p) / C(n,w).
```

## Stern-style collision baseline

The executable Stern step keeps a size-`k` information set, splits it into two halves, enumerates weight-`p` partial sums in both halves, and collides them on `l` selected parity coordinates.

The modeled useful-set probability is:

```text
C(|I1|,p) * C(|I2|,p) * C(r-l,w-2p) / C(n,w).
```

The expected number of projection collisions is modeled as `L1*L2/2^l`.

## Dumer-style enlarged-information-set baseline

Dumer's collision step moves the `l` collision coordinates *into* the information region. The executable implementation chooses `J` with size `r-l`, row-reduces the selected parity columns to partial systematic form

```text
H_J -> [ I_(r-l) ]
       [    0_l  ]
```

and lets the complement `I` have size `k+l`.

The enlarged information region is split into two halves. For even `p`, the decoder enumerates weight-`p/2` subsets in each half, collides the two lists on the bottom `l` transformed syndrome equations, and solves the remaining `r-l` selected coordinates directly from the top equations.

For half sizes `a=floor((k+l)/2)` and `b=k+l-a`, the exact split event used by this implementation is:

```text
C(a,p/2) * C(b,p/2) * C(r-l,w-p) / C(n,w).
```

The expected list collision count under the random-code heuristic is:

```text
C(a,p/2) * C(b,p/2) / 2^l.
```

The reduced implementation verifies every recovered candidate against the public syndrome, so the estimator is backed by an executable attack mechanism rather than a formula-only stub.

## Cost models

`lee_brickell_cost_point()` uses:

```text
elimination cost per sampled set ~= r^3
per-guess work                  ~= (p+2)r
```

`stern_cost_point()` and `dumer_cost_point()` separately report elimination, list-generation, collision, and memory work. Their list/collision terms are intentionally simple reference counts, not optimized implementation costs.

All `log2(operations)` outputs are for **relative research screening only**. They omit optimized bit-slicing, Gray-code/list updates, cache effects, some systematicization probabilities, and later representation techniques.

## Why this is still intermediate

Dumer-style enlarged sets improve the attack baseline, but MMT/BJMM-style representation algorithms can reduce work further. Any later estimator must keep explicit time, memory, list sizes, success probability, and reduced executable validation wherever feasible.

## Primary literature direction

- Lee and Brickell, *An Observation on the Security of McEliece's Public-Key Cryptosystem*.
- Jacques Stern, *A Method for Finding Codewords of Small Weight*, 1989.
- Ilya Dumer, *Two Decoding Algorithms for Linear Codes*, 1989.
- Christiane Peters, *Information-Set Decoding for Linear Codes over F_q*, 2010.
- May, Meurer, and Thomae, *Decoding Random Linear Codes in O(2^0.054n)*, 2011.
- Becker, Joux, May, and Meurer, *Decoding Random Binary Linear Codes in 2^(n/20)*, 2012.

The repository's claims remain limited to the mechanisms and cost accounting actually implemented here.

## Run

```bash
python experiments/lee_brickell_probe.py
python experiments/stern_probe.py
python experiments/dumer_probe.py
```
