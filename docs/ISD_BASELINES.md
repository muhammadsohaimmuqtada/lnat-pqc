# Information-set decoding baselines

## Status

The public random-code relation used by the research bridge/KEM must be evaluated as a syndrome-decoding target. No LNAT master-seed length is used as a substitute for decoding work.

The repository now has three executable information-set decoding baselines:

1. **Prange-style decoding** in `src/code_attacks.py`;
2. **Lee-Brickell-style generalized ISD** in `src/code_isd.py`;
3. **Stern-style collision/list ISD** in `src/code_stern.py`.

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

## Stern-style collision baseline

The executable Stern step keeps the same systematic-information-set setup but avoids enumerating every `2p`-subset directly.

After transforming the target and information-set columns through `H_J^-1`, split the `k` information positions into two halves `I1` and `I2`. Enumerate weight-`p` partial sums in both halves and match them on `l` selected coordinates of the transformed parity solution.

A useful sampled set for this implementation has:

- exactly `p` errors in `I1`;
- exactly `p` errors in `I2`;
- zero errors in the `l` collision-filter parity coordinates;
- the remaining `w-2p` errors in the other `r-l` parity coordinates.

Ignoring invertibility of `H_J`, the modeled event probability is:

```text
C(|I1|,p) * C(|I2|,p) * C(r-l,w-2p) / C(n,w).
```

The left list has `C(|I1|,p)` entries, the right list has `C(|I2|,p)` entries, and the expected number of projection collisions under the random-code heuristic is modeled as:

```text
C(|I1|,p) * C(|I2|,p) / 2^l.
```

The reduced-parameter implementation validates the mechanism by recovering the exact public sparse witness, rather than adding an estimator that has never been exercised.

## Cost models

`lee_brickell_cost_point()` uses:

```text
elimination cost per sampled set ~= r^3
per-guess work                  ~= (p+2)r
```

`stern_cost_point()` separately reports:

```text
elimination work ~= r^3
list work        ~= (L1 + L2) * p * r
collision work   ~= (L1 * L2 / 2^l) * r
memory entries   ~= L1
```

where `L1=C(|I1|,p)` and `L2=C(|I2|,p)`.

These counts are intentionally simple Python/reference-operation models. They omit optimized bit-slicing, Gray-code/list-update techniques, the probability that `H_J` is invertible, and later ISD improvements. Their `log2(operations)` values are for relative research screening only and must not be presented as a proven security level.

## Why this is still intermediate

Stern-style collisions are stronger than the current Prange/Lee-Brickell baselines, but Dumer and later BJMM/MMT-style algorithms can reduce work further. The next estimator should therefore retain explicit list sizes, collision conditions, memory, success probability, and an executable reduced-parameter validation whenever feasible.

## Primary literature direction

- Lee and Brickell, *An Observation on the Security of McEliece's Public-Key Cryptosystem*.
- Jacques Stern, *A Method for Finding Codewords of Small Weight*, 1989.
- Christiane Peters, *Information-Set Decoding for Linear Codes over F_q*, IACR ePrint 2009/589 / PQCrypto 2010.

The repository's claims remain limited to the mechanisms and cost accounting actually implemented here.

## Run

```bash
python experiments/lee_brickell_probe.py
python experiments/stern_probe.py
```
