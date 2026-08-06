# LNAT-PQC

**Learning Noisy Automata Transitions — experimental cryptography research**

LNAT is a research prototype exploring whether noisy finite-state transition systems can support useful cryptographic constructions on constrained hardware.

> **Pre-publication research prototype:** LNAT has not received independent cryptanalysis or external peer review. The repository does not establish a new accepted hardness assumption, a proven security level, or production-ready post-quantum security. Do not use it to protect real data.

## Research question

The project studies a simple idea: if a secret state-transition process is observed only through noisy input/output traces, can recovering the hidden transition behavior be made computationally difficult enough to support a cryptographic construction?

The repository contains reference code, experiments, parameter sketches, known-answer tests, and a draft paper used to investigate that question.

## Current scope

The current milestone focuses on the KEM prototype and reproducible experimentation:

- reference Python implementation
- parameter sets used by the prototype
- key generation / encapsulation / decapsulation round-trip tests
- known-answer test vectors
- basic performance experiments
- documentation of open security questions

The signature construction remains exploratory.

## Repository structure

```text
lnat-pqc/
├── src/
│   ├── lnat_core.py
│   ├── lnat_kem.py
│   ├── lnat_sign.py
│   └── lnat_params.py
├── tests/
│   ├── test_kem.py
│   ├── test_hardness.py
│   ├── test_vectors.py
│   └── vectors/
├── benchmarks/
│   └── bench.py
├── reference/
│   └── hard_problem_demo.py
├── docs/
│   ├── CONSTRUCTION.md
│   ├── SECURITY.md
│   ├── PARAMETERS.md
│   └── CONTRIBUTING.md
├── paper/
│   └── lnat_research_paper.docx
└── README.md
```

## Quick start

```bash
git clone https://github.com/muhammadsohaimmuqtada/lnat-pqc.git
cd lnat-pqc
pip install -r requirements.txt
python tests/test_kem.py
```

Run the broader experimental checks with:

```bash
python tests/test_hardness.py
python tests/test_vectors.py
```

## Construction overview

At a high level, the prototype derives a secret transition process from private key material, produces public observations from selected transition traces, and experiments with noisy recovery mechanisms for encapsulation and decapsulation.

The construction is intentionally kept in reference form so that assumptions, serialization choices, error handling, and parameter behavior can be inspected and challenged.

For the algorithm specification, see [docs/CONSTRUCTION.md](docs/CONSTRUCTION.md).

## Open research problems

The important work is not implementation polish; it is establishing whether the underlying idea is secure at all. Current open questions include:

- formal definition of the computational problem
- reduction or security proof for the KEM construction
- attacks exploiting transition structure or observation leakage
- parameter selection backed by cryptanalytic evidence
- error-correction design
- chosen-ciphertext security
- side-channel behavior and constant-time implementation
- independent cryptanalysis

See [docs/SECURITY.md](docs/SECURITY.md) for the current security notes.

## Comparison with standardized PQC

LNAT should not be presented as an alternative with security parity to standardized schemes such as ML-KEM. ML-KEM has undergone years of public cryptanalysis and standardization; LNAT has not.

Any implementation-size or performance comparisons in this repository should therefore be interpreted as engineering measurements of prototypes, not evidence of equivalent cryptographic security.

## Contributing

The most useful contributions are skeptical ones:

- cryptanalysis and counterexamples
- independent implementations
- parameter analysis
- reproducible benchmarks
- review of the proposed hardness assumptions
- corrections to the draft construction or paper

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Research paper

The current draft is stored in `paper/lnat_research_paper.docx`. It should be treated as a working research document rather than a peer-reviewed publication.

## Status

- [x] Reference construction implemented
- [x] KEM round-trip experiments
- [x] Known-answer test infrastructure
- [x] Draft security notes
- [ ] Formal security proof
- [ ] Robust error-correction design
- [ ] Constant-time implementation
- [ ] Independent implementation
- [ ] External cryptanalysis
- [ ] Peer-reviewed publication

## License

MIT License.

## Security disclaimer

This repository is experimental cryptography. Passing unit tests only demonstrates implementation consistency for the tested cases; it does not demonstrate cryptographic security.