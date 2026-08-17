# LNAT Research Roadmap

## Stage 0 — negative-result reset — complete

- reproduce KEM-v1 public-data break;
- remove unsupported security-level claims;
- separate primitive research from KEM claims;
- establish CI and negative regression tests.

## Stage 1 — primitive specification — complete for EXP2

- exact transition/observation/noise semantics;
- explicit domain separation;
- keyed observation function;
- deterministic known-answer vector;
- canonical bit packing and validation.

## Stage 2 — attack harness — active

Completed:

- exhaustive seed recovery for tiny spaces;
- noisy multi-trace scoring;
- monobit and lag-1 statistical probes;
- held-out Markov next-bit prediction;
- machine-readable parameter sweeps;
- known-break regression;
- executable Prange, Lee-Brickell, and Stern random-code attacks;
- pinned modern classical syndrome-decoding estimator bridge;
- direct sparse-support attack ceiling;
- transparent Groverized-Prange/support-enumeration quantum-search rejection screen;
- unified classical + quantum-baseline + correctness frontier API;
- focused combined-screen measurement with an adjacent `1692` reject / `1694` pass boundary at rate 1/2 and `w=230`;
- paper-grounded Prange logical-qubit and asymptotic-depth resource accounting, pinned to the authors' `qiboteam/qISD` supplementary implementation;
- Theorem-1 Hybrid-Prange constrained-memory/time trade-off with an integer finite interface for classically guessed zero coordinates.

Current findings:

- `(1064,532,w=117)` crosses the current 128-bit **classical** estimator screen but is rejected as a post-quantum frontier point because the Groverized-Prange search exponent is only about `63.68` iteration bits.
- `(1692,846,w=230)` clears the 128-bit Groverized-Prange baseline and correctness gate but is rejected by BJMMplus at `127.865290976502` modeled classical bits.
- `(1694,847,w=230)` clears the currently implemented combined screen with BJMMplus at `128.408410067763`, Groverized-Prange at `128.025066962080` iteration bits, and conservative KEM failure `8.82707240635e-10`.
- The Esser et al. Prange circuit-resource model for `(1694,847,w=230)` requires `721,643` logical qubits in the width-optimized layout or `1,438,205` in the depth-oriented full layout. The literal Table-2 width-optimized big-O depth scale has log2 value about `163.627`; this is not an exact gate-depth/security metric.
- Hybrid-Prange exposes the cost of limiting matrix memory. On `(1694,847,w=230)`, retaining 169 of 847 quantum information coordinates uses `143,143` matrix-representation qubits (~19.95% of the full matrix term) and gives Theorem-1 time exponent `t≈0.86455`; retaining 85 coordinates (~10.04% matrix memory) gives `t≈0.92832`. These are asymptotic trade-off exponents, not finite attack-bit estimates.

The `1694` point is only the smallest measured pass in the focused fixed-weight bracket. It is **not** a post-quantum security level or deployment recommendation because the quantum search screen is only a rejection baseline and stronger quantum ISD is not yet modeled finitely.

Next:

- port/cross-check the paper's Punctured-Hybrid and Combined-Hybrid resource trade-offs using their exact finite combinatorics before any approximation;
- finite best-known quantum ISD analysis beyond Groverized Prange, prioritizing Kachigar--Tillich/Kirshanova-style attacks without inventing finite heuristics;
- concrete reversible-oracle/gate-depth resource accounting beyond the current big-O Prange depth scale;
- explicit qRAM/quantum-memory assumptions for stronger quantum ISD;
- stronger trained distinguishers with held-out evaluation;
- collision/state-merging experiments;
- time-memory tradeoffs for seed recovery;
- SAT/SMT only where the modeled construction is meaningful;
- automated experiment-result archiving.

## Stage 3 — operational integration — complete as research profile

`LNAT-MLKEM768-HYBRID-v1` provides KeyGen/Encap/Decap, ML-KEM-768 backend, deterministic LNAT post-processing, versioned serialization, context binding, tests, and CI.

Its security boundary remains ML-KEM-768, not standalone LNAT.

## Stage 4 — asymmetric research — blocked on mathematics/security evidence

Do not create a standalone LNAT KEM merely by rearranging public traces. First identify a public operation an encapsulator can perform and a private trapdoor that enables only the recipient to invert/reconcile it.

The `LNAT-CODE-*` line is useful as a comparator because it supplies an explicit random-code asymmetric relation, but its hardness comes from syndrome decoding rather than a new LNAT assumption. It must pass both classical and quantum cryptanalysis before parameter promotion, and it does not by itself solve the LNAT-native trapdoor problem.

If no LNAT-native asymmetric relation emerges, LNAT should remain a research PRF/state-machine transform instead of being forced into a standalone KEM.

## Stage 5 — only after a defensible standalone construction

- formal reduction or clearly stated assumption;
- concrete classical and quantum parameter estimates;
- failure bounds;
- CCA analysis;
- constant-time implementation;
- independent implementation and cryptanalysis;
- embedded benchmarks.
