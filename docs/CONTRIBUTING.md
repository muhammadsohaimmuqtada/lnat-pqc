# Contributing to LNAT-PQC Research

The highest-value contribution is evidence: attacks, counterexamples, independent implementations, reproducible measurements, and specification corrections.

## Before changing the construction

Algorithm changes must answer:

1. What exact weakness or research question does the change address?
2. Does the mathematical specification change?
3. Does domain separation/versioning need to change?
4. Which known-answer vectors change?
5. Which attack should be rerun?
6. Does the change create a new security claim? If so, what proof or evidence supports it?

## Required checks

```bash
python -m unittest discover -s tests -v
python attacks/public_recovery_v1.py
python attacks/exhaustive_seed_recovery.py --seed-bits 8 --traces 3 --noise 0.05
python attacks/statistical_probe.py --samples 8
python -m compileall -q src tests attacks benchmarks experiments
```

With the PQC extra installed:

```bash
python src/lnat_hybrid_kem.py
python benchmarks/bench.py --rounds 5 --hybrid
```

## Cryptanalysis reports

Include commit SHA, exact profile, sample count, attacker knowledge, success criterion, runtime/memory, reproduction commands, and whether the result is a full break, distinguisher, predictor, recovery attack, or observation.

Failed attacks are useful when methodology and limits are documented.

## Security language

Do not describe state size as security bits. Do not assign NIST levels to standalone LNAT. Do not describe a passing statistical test as evidence of cryptographic pseudorandomness.

The operational hybrid may accurately state that it uses ML-KEM-768 as its KEM backend, but must not imply that LNAT independently provides the standardized security property.
