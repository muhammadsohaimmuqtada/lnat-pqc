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
- known-break regression.

Next:

- stronger trained distinguishers with held-out evaluation;
- collision/state-merging experiments;
- time-memory tradeoffs for seed recovery;
- SAT/SMT only where the modeled construction is meaningful;
- automated experiment-result archiving.

## Stage 3 — operational integration — complete as research profile

`LNAT-MLKEM768-HYBRID-v1` provides KeyGen/Encap/Decap, ML-KEM-768 backend, deterministic LNAT post-processing, versioned serialization, context binding, tests, and CI.

Its security boundary remains ML-KEM-768, not standalone LNAT.

## Stage 4 — standalone asymmetric construction — blocked on mathematics

Do not create KEM-v2 merely by rearranging public traces. First identify a public operation an encapsulator can perform and a private trapdoor that enables only the recipient to invert/reconcile it.

If no such relation emerges, LNAT should remain a research PRF/state-machine transform instead of being forced into a standalone KEM.

## Stage 5 — only after a defensible standalone construction

- formal reduction or clearly stated assumption;
- concrete parameter estimates;
- failure bounds;
- CCA analysis;
- constant-time implementation;
- independent implementation and cryptanalysis;
- embedded benchmarks.
