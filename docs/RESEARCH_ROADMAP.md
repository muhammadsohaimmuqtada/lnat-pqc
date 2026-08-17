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
- transparent Groverized-Prange/support-enumeration quantum-search screen.

Current negative result:

- `(1064,532,w=117)` crosses the current 128-bit **classical** estimator screen but is rejected as a post-quantum frontier point because the Groverized-Prange search exponent is only about `63.68` bits. This is an iteration/query model, not a quantum gate-security estimate.

Next:

- finite best-known quantum ISD analysis beyond Groverized Prange;
- concrete reversible-oracle/time/memory resource accounting for any serious code point;
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
