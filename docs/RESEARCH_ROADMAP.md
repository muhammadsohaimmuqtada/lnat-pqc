# Research Roadmap

## Stage 0 — cryptanalytic reset

- [x] Mark KEM-v1 broken.
- [x] Add reproducible public-recovery attack.
- [x] Remove state-size security claims.
- [x] Define transition/observation order exactly.
- [x] Separate correctness tests from hardness evidence.
- [x] Quarantine insecure KEM construction behind explicit acknowledgement.

## Stage 1 — define the primitive as a research problem

- [ ] Define one or more formal distinguishing/recovery games.
- [ ] Define the adversary's oracle/sample access precisely.
- [ ] Define single-trace versus multi-trace settings.
- [ ] Define success metrics and advantage.
- [ ] Specify tiny parameter profiles intended for attacks.

## Stage 2 — attack harness

- [ ] Exhaustive search baselines.
- [ ] SAT model.
- [ ] SMT model.
- [ ] Statistical distinguishers.
- [ ] State-prediction/correlation attacks.
- [ ] Automated parameter sweeps.
- [ ] Reproducible experiment outputs.

## Stage 3 — evaluate the primitive

- [ ] Measure attack scaling across tiny parameters.
- [ ] Look for trace biases and structural leakage.
- [ ] Compare observation functions.
- [ ] Compare noise models.
- [ ] Study seed reuse and multi-trace leakage.
- [ ] Decide whether the primitive is worth pursuing.

## Stage 4 — only if justified: asymmetric construction research

- [ ] Identify a genuine public/private asymmetry or trapdoor.
- [ ] Specify correctness and decapsulation-failure behavior.
- [ ] Construct KEM-v2.
- [ ] Attempt direct breaks before writing security claims.
- [ ] Define and analyze IND-CPA only after the base construction survives basic attacks.
- [ ] Consider CCA transformation only after that.

## Stage 5 — engineering

- [ ] Stable serialization.
- [ ] Known-answer vectors.
- [ ] CI across supported Python versions.
- [ ] Independent implementation.
- [ ] Constant-time implementation strategy.
- [ ] Embedded benchmarks.
