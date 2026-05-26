# Contributing to LNAT-PQC

Thank you for your interest. This is an early-stage research project.
All contributions are welcome — especially attacks.

---

## Most Valuable Contributions

### 1. Cryptanalysis (most valuable)
Try to break LNAT. Seriously. This is the most important thing.

If you find a weakness, please open a GitHub Issue titled
`[CRYPTANALYSIS] <description>` and describe:
- What attack you attempted
- What parameters you used
- What you found (even partial results are valuable)
- Whether it was a full break, a distinguishing attack, or an observation

Failed attacks are also valuable — document them.

### 2. Formal Security Proofs
The security reduction from LNAT-KEM to the LNAT problem needs
to be formalized completely. If you have experience with provable
security and game-based proofs, this is the highest-value theoretical
contribution.

See `docs/SECURITY.md` for the current proof sketch.

### 3. Independent Implementations
An independent implementation in any language helps verify the
construction is correctly specified. C, Rust, Go, and Java
are most useful. Please include:
- Test vectors matching `tests/vectors/kat_128.json`
- Benchmark numbers on your hardware
- Any bugs or ambiguities you found in the spec

### 4. Performance Optimization
The lazy PRF tree optimization (see `docs/CONSTRUCTION.md`)
is the highest-priority performance work. BCH error correction
to replace the current repetition code is the second priority.

---

## What NOT to do

- Do not submit a pull request claiming LNAT is broken
  without reproducible details
- Do not add dependencies without discussion
- Do not change the algorithm without opening an issue first
- Do not use this code in any real system and then report
  it as a vulnerability — it is not production code

---

## How to Submit Code

1. Fork the repository
2. Create a branch: `git checkout -b your-feature`
3. Make your changes
4. Run the tests: `python tests/test_kem.py`
5. Open a pull request with a clear description

---

## Code Style

- Python: PEP 8, clear variable names, comments explaining WHY not WHAT
- Every function must have a docstring
- Security-critical code must have comments explaining the security rationale
- Never use `random` module — always use `secrets` or `os.urandom`

---

## Reporting Vulnerabilities

If you find a serious vulnerability in the construction (not just
the reference implementation), please open a GitHub Issue immediately.

Label it `[VULNERABILITY]`. Describe what you found.
There is no bug bounty — this is academic research.
But you will be credited in the paper.

---

## Contact

Open a GitHub Issue for any question.
This is the preferred communication channel so discussions
are public and searchable.
