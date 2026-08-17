# Contributing to LNAT-PQC

LNAT is early-stage experimental cryptography. The highest-value contributions are reproducible attacks, counterexamples, precise definitions, and independent implementations.

## Cryptanalysis

A useful cryptanalysis report should include:

- the exact commit and parameter profile;
- the attack model and information available to the attacker;
- runnable code or sufficiently precise pseudocode;
- measured success rate and work factor;
- whether the result is a full break, distinguisher, recovery attack, bias, or negative result.

A failed attack is useful when its model and limitations are documented, but failure of one attack must not be described as proof of hardness.

## Algorithm changes

Changes to the primitive or a future KEM should include:

- an updated specification;
- new correctness tests;
- an explicit threat model;
- adversarial regression tests where applicable;
- documentation of which previous results/test vectors become invalid.

Do not add security-level or NIST-level claims without a defensible cryptanalytic basis and review.

## Running checks

```bash
python -m unittest discover -s tests -v
python attacks/public_recovery_v1.py
python -m compileall -q src tests attacks
```

The public-recovery attack is expected to succeed because it documents the archived KEM-v1 break.

## Code style

- Prefer clear reference code over premature optimization.
- Use explicit exceptions rather than `assert` for input validation.
- Use `secrets` for cryptographic randomness in reference code.
- Domain-separate cryptographic function invocations.
- Document security rationale and uncertainty explicitly.

## Responsible framing

Do not present LNAT as production-ready, standardized, peer-reviewed, or equivalent in security to standardized post-quantum algorithms. The repository is intended to make the research easy to inspect and challenge.
