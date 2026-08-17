# Quantum Prange resource accounting

This document tracks the concrete resource surface of the **currently implemented quantum attack baseline** against the random-code research line. It does not assign a post-quantum security level.

## Primary source and provenance

The resource model is grounded in:

- Andre Esser, Sergi Ramos-Calderer, Emanuele Bellini, José I. Latorre, Marc Manzano, *An Optimized Quantum Implementation of ISD on Scalable Quantum Resources*, Cryptology ePrint 2021/1608 / arXiv:2112.06157.
- the paper's supplementary implementation: `qiboteam/qISD`.
- pinned supplementary-code revision: `456b3c60987e426a18d4ed4e5ebeaee3d2570958`.

The paper derives Prange's success probability

```text
q = C(n-k,w) / C(n,w)
```

and applies amplitude amplification. Its Table 2 gives explicit logical-qubit formulas and an asymptotic depth expression for the full Prange circuit. Section 6 then introduces classical co-processors that reduce the quantum-memory requirement while retaining a quantum speedup.

The supplementary qISD repository constructs the circuits in Qibo, emits QASM/circuit summaries, and intentionally limits execution to small simulated circuits. We therefore use the paper's closed-form resource formulas for large research parameters rather than pretending a 700k-qubit Qibo simulation is practical.

## Units kept separate

`src/code_quantum_prange_resources.py` reports:

1. **Prange success probability / expected trials** — a combinatorial search model.
2. **Idealized Grover iteration count** — amplitude-amplification oracle iterations, including the `pi/4` leading constant in the tiny-success-probability approximation.
3. **Logical qubits** — exact values from the paper's Table-2 width formulas.
4. **Width-optimized depth scale** — the logarithm of the Table-2 big-O quantity

```text
n^3 log(n) / sqrt(q)
```

The fourth value keeps the published asymptotic expression literal. It does **not** inject the separate `pi/4` Grover constant because Table 2 states the depth only up to big-O multiplicative constants. It is deliberately called a **scale**, not an exact circuit depth, and does not by itself provide a Toffoli count, Clifford+T count, surface-code cost, wall-clock time, or security level.

`src/code_hybrid_prange_tradeoff.py` separately reports the paper's **Hybrid-Prange Theorem-1** trade-off:

- matrix-representation qubit fraction `delta`;
- integer classically guessed zero coordinates;
- reduced quantum instance `(n-a, k-a, w)`;
- matrix-representation qubits `(n-k)(k-a)`; and
- dimensionless asymptotic time exponent `t(delta)` where the paper writes the hybrid running time as `T_C ^ t(delta)`.

The Hybrid-Prange matrix-memory term is not total circuit width, and `t(delta)` is not a finite gate-count exponent.

## Current focused combined-screen point

For the measured research point `(n=1694,k=847,w=230)`:

```text
Prange expected-trial bits                256.050133924
Prange success probability                ~8.3412e-78
idealized Grover iteration bits            127.676563092
idealized Grover iterations                ~2.7194e38
width-optimized logical qubits             721,643
depth-oriented full logical qubits         1,438,205
Table-2 width-optimized depth-scale bits   163.626791037
```

The width-optimized logical-qubit formula is

```text
(n-k+2)(k+3)-7
```

and the depth-oriented full-circuit logical-qubit formula is

```text
(n-k+1)(n+2)-3.
```

These figures make the resource assumption visible: even the width-optimized published Prange circuit needs roughly 0.72 million logical qubits for this point.

## Hybrid-Prange constrained-memory examples

Theorem 1 defines `delta=1` as the full-quantum matrix footprint and `delta=0` as the classical endpoint. To keep finite dimensions integral, the implementation takes an integer number `a` of classically guessed zero coordinates; then

```text
retained quantum dimension = k-a
delta = (k-a)/k
reduced quantum instance = (n-a, k-a, w)
matrix-representation qubits = (n-k)(k-a)
```

For `(1694,847,230)`:

```text
a = 0
  retained k'                 847
  matrix qubits               717,409
  matrix-memory fraction      1.000000
  Hybrid-Prange t(delta)      0.500000

 a = 423
  retained k'                 424
  matrix qubits               359,128
  matrix-memory fraction      0.500590
  Hybrid-Prange t(delta)      0.702451

 a = 678
  retained k'                 169
  reduced instance            (1016,169,230)
  matrix qubits               143,143
  matrix-memory fraction      0.199528
  Hybrid-Prange t(delta)      0.864551

 a = 762
  retained k'                 85
  matrix qubits               71,995
  matrix-memory fraction      0.100354
  Hybrid-Prange t(delta)      0.928318

 a = 847
  retained k'                 0
  matrix qubits               0
  matrix-memory fraction      0.000000
  Hybrid-Prange t(delta)      1.000000
```

The endpoints reproduce the theorem: full quantum gives exponent `1/2`, while zero quantum matrix memory returns the classical exponent `1`. Less quantum memory monotonically increases the asymptotic time exponent for this point.

These numbers must not be converted mechanically into a finite attack-bit claim. The theorem's `T_C` is an asymptotic classical running-time model, while the finite repository estimator reports separate concrete/modelled costs. The purpose here is to make the quantum-memory/time trade-off explicit.

## What this changes

The earlier `code_quantum_isd.py` value of about `128.025` for `(1694,847,w=230)` is an exponent-only **rejection baseline** based on halving the classical Prange search exponent. The resource modules now expose both the full-width Prange circuit footprint and the paper's constrained-memory Hybrid-Prange trade-off.

This does **not** make `(1694,847,w=230)` secure. Stronger quantum ISD algorithms such as the Kachigar--Tillich/Kirshanova quantum-walk variants remain outside the finite resource model, and the current Prange depth expression is asymptotic rather than a fault-tolerant gate estimate.

## Reproduce

```bash
python experiments/quantum_prange_resource_probe.py \
  --n 1694 --k 847 --weight 230 \
  --expect-width-qubits 721643 \
  --expect-depth-qubits 1438205

python experiments/hybrid_prange_tradeoff_probe.py \
  --n 1694 --k 847 --weight 230 \
  --guess-zeros 0 \
  --guess-zeros 423 \
  --guess-zeros 678 \
  --guess-zeros 762 \
  --guess-zeros 847
```

## Next required quantum work

Before any random-code parameter can be promoted beyond research status:

1. implement or independently cross-check a finite stronger quantum-ISD attack model;
2. extend resource-constrained analysis to the paper's Punctured-Hybrid and Combined-Hybrid trade-offs where their finite combinatorics can be reproduced faithfully;
3. account for the quantum memory/qRAM assumptions of stronger quantum ISD;
4. derive concrete reversible-oracle/gate-depth resources rather than only big-O depth;
5. obtain independent cryptanalysis.

Until then, the standardized ML-KEM-768-backed hybrid remains the operational post-quantum path in this repository.
