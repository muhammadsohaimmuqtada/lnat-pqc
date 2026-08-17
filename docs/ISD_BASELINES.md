# Information-set decoding baselines

## Status

The public random-code relation used by the research bridge/KEM must be evaluated as a syndrome-decoding target. No LNAT master-seed length is used as a substitute for decoding work.

The repository now has two executable information-set decoding baselines:

1. **Prange-style decoding** in `src/code_attacks.py`;
2. **Lee-Brickell-style generalized ISD** in `src/code_isd.py`.

These are attack baselines, not security proofs.

## Lee-Brickell generalization

Let the public code have length `n`, dimension `k`, parity dimension `r=n-k`, and hidden error weight `w`.

Choose an information set `I` of size `k` and its complement `J` of size `r`. If the parity-check submatrix on `J` is invertible, guess that exactly `p` error positions lie in `I`. For each weight-`p` guess:

1. subtract the guessed information-set syndrome from the public target;
2. solve the remaining square system on `J`;
3. accept if the solved part has weight `w-p`.

`p=0` is the Prange event. `p>0` spends more cheap guesses inside one information set in exchange for a higher probability that a sampled set is useful.

Ignoring the probability that the selected square submatrix is invertible, the exact combinatorial event probability is:

```text
C(k,p) * C(n-k,w-p) / C(n,w).
```

The executable attack separately reports sampled information sets, invertible sets, and guesses tested.

## Cost model

`lee_brickell_cost_point()` includes a deliberately simple implementation-cost model:

```text
elimination cost per sampled set ~= (n-k)^3
per-guess work                  ~= (p+2)(n-k)
```

and combines this with the expected information-set count.

This is useful for choosing `p` in the reference Python implementation. It is **not** a modern ISD security estimator and the resulting `log2(operations)` must not be presented as a proven security level.

## Why this is an intermediate step

Stern/Dumer-style collision methods and later ISD algorithms reduce decoding work further by using meet-in-the-middle/list techniques. Before adding those formulas to the parameter frontier, this repository requires either:

- an executable reduced-parameter attack matching the modeled mechanism; or
- a carefully sourced estimator whose list sizes, success probability, memory cost, and operation model are explicit.

The project will not replace Prange with an unverified single-number formula.

## Primary literature direction

The relevant progression includes:

- Lee and Brickell, *An Observation on the Security of McEliece's Public-Key Cryptosystem*;
- Stern, *A Method for Finding Codewords of Small Weight*;
- Peters, *Information-Set Decoding for Linear Codes over F_q*.

These references motivate increasingly strong ISD families. The repository's own claims remain limited to what its executable attacks and explicit cost models actually implement.

## Run

```bash
python experiments/lee_brickell_probe.py
```
