# Punctured-Hybrid and Combined-Hybrid proof accounting

This note records the finite combinatorial factors implemented from Theorem 2 and Theorem 3 of Esser et al., *An Optimized Quantum Implementation of ISD on Scalable Quantum Resources* (ePrint 2021/1608 / arXiv:2112.06157), cross-checked against the authors' `qiboteam/qISD` `hybrid.sage` implementation pinned at commit `456b3c60987e426a18d4ed4e5ebeaee3d2570958`.

The output is **not a finite quantum gate count or a security level**. The paper states the running times with soft-O notation, so polynomial factors and concrete circuit constants remain omitted.

## Integer finite parameters

For a binary `[n,k]` syndrome-decoding instance of target weight `w`:

- `a` = classically guessed zero coordinates;
- `b` = omitted parity-check equations / punctured coordinates;
- `p` = target weight on the omitted part;
- `u = w-p` = target weight of the reduced quantum instance.

The reduced quantum code has

```text
N  = n-a-b
k' = k-a
r' = n-k-b
u  = w-p
```

and the matrix-representation term is

```text
k' r' = (k-a)(n-k-b).
```

Punctured-Hybrid is the `a=0` specialization. Combined-Hybrid allows `a>0` before invoking the Punctured-Hybrid subroutine.

## Explicit proof factors

Let `L(N,t) = log2(C(N,t))`.

### Correct zero guess

Combined-Hybrid first guesses `a` zero coordinates. The proof gives

```text
q_zero = C(n-a,w) / C(n,w)
```

so

```text
log2(q_zero) = L(n-a,w) - L(n,w).
```

For Punctured-Hybrid, `a=0` and this factor is exactly one.

### Expected outer Punctured-Hybrid permutations

Theorem 3 defines

```text
E = C(n-a,w) / [ C(N,u) C(b,p) ].
```

Theorem 2 is again the `a=0` specialization.

### Expected reduced-instance solutions

The proof gives

```text
S_expected = C(N,u) 2^(-r').
```

Because the algorithm knows at least one solution exists on the successful branch, the quantum/repetition accounting uses

```text
M = max(1, S_expected).
```

### Quantum subroutine factor

The proof's reduced quantum search contributes

```text
T_Q = O~( sqrt( C(N,u) / [ M C(r',u) ] ) ).
```

### Total explicit proof-component proxy

The implemented log2 proxy is therefore

```text
Combined:
  -log2(q_zero) + log2(E) + log2(T_Q without O~ factors) + log2(M)

Punctured:
  log2(E) + log2(T_Q without O~ factors) + log2(M).
```

The repository calls this `proof_time_proxy_bits`. The suffix `bits` means only a base-2 logarithm of the explicit multiplicative proof factors. It must not be presented as cryptographic security bits.

## Current `(1694,847,w=230)` reference points

### Punctured-Hybrid near 20% matrix memory

```text
a = 0
b = 678
p = 204
reduced instance              (1016, 847, 26)
retained parity checks        169
matrix-representation qubits  143,143
matrix-memory fraction        0.199527744982
log2(E)                       201.421657731467
log2(S_expected)                1.858446431301
log2(T_Q proxy)                33.942313055373
proof-time proxy              237.222417218141
```

For fixed `a=0,b=678`, exhaustive finite optimization over feasible integer `p` selects `p=204`.

### Combined-Hybrid near 20% matrix memory

```text
a = 582
b = 306
p = 86
reduced instance              (806, 265, 144)
retained parity checks        541
matrix-representation qubits  143,365
matrix-memory fraction        0.199837191895
log2(q_zero)                 -152.952582664670
log2(E)                        13.766808528875
log2(S_expected)                0.002771887139
log2(T_Q proxy)                46.727703346479
proof-time proxy              213.449866427162
```

For fixed `a=582,b=306`, exhaustive finite optimization over feasible integer `p` selects `p=86`.

At almost the same matrix-representation footprint, this Combined-Hybrid point has a lower **theorem proof-component proxy** than the Punctured-Hybrid point. This is an attack-model comparison only; it is not a claim that either number is an exact runtime or security level.

Additional fixed examples currently regression-tested are:

```text
Combined ~10% matrix memory:
  a=658, b=468, p=129
  matrix fraction       0.0998468098393
  proof-time proxy      226.904432335904

Combined ~1% matrix memory:
  a=780, b=740, p=202
  matrix fraction       0.00999290502349
  proof-time proxy      248.622721150773
```

## Reproduce

```bash
python experiments/punctured_combined_hybrid_probe.py \
  --n 1694 --k 847 --weight 230 \
  --guess-zeros 0 --omit 678

python experiments/punctured_combined_hybrid_probe.py \
  --n 1694 --k 847 --weight 230 \
  --guess-zeros 582 --omit 306
```

Omitting `--p` runs a finite exhaustive search over feasible integer `p` while keeping `a` and `b` fixed.

## Remaining blocker

This model faithfully exposes the paper's explicit finite combinatorial factors, but it still suppresses polynomial/circuit constants and it is not a best-known quantum-ISD gate/resource estimator. The random-code research line remains non-deployable until stronger quantum ISD, qRAM/memory assumptions, concrete reversible-circuit resources, and independent cryptanalysis are addressed.
