# LNAT-PQC

**Learning Noisy Automata Transitions — Post-Quantum Cryptographic Primitive**

> ⚠️ **Research Proposal — Pre-Publication Draft**
> This is not production software. Do not use in any real system.
> The construction is under active development and has not received
> external cryptographic review. Use for research and experimentation only.

---

## What is LNAT?

LNAT (Learning Noisy Automata Transitions) is a new computational hardness
assumption for post-quantum cryptography. It is based on the infeasibility
of recovering the transition function of a nonlinear finite automaton from
noisy observations.

**The hard problem in one sentence:**
Given many (input → noisy output) pairs from a secret machine,
reconstruct the machine's internal rules.

This is computationally intractable because:
- The rules table has 2^(n+m) entries at n=128 bits — more combinations
  than atoms in the observable universe
- The noise corrupts just enough output to prevent reconstruction
- No known quantum algorithm provides more than a quadratic (Grover)
  speedup — insufficient at n=256

---

## Why LNAT?

| Property | Kyber (ML-KEM) | Picnic | LNAT (this work) |
|---|---|---|---|
| Hard problem | MLWE (lattice) | MPC satisfiability | LNAT (automata) |
| Quantum resistance | Grover only | Grover only | Grover only |
| NTT required | Yes | No | **No** |
| Core operations | Poly. multiply | MPC simulation | **XOR + array lookup** |
| Low-end hardware | Moderate | Poor | **Excellent** |
| Public key size | ~1.1 KB | ~32 KB | ~200 bytes (est.) |
| Maturity | NIST Standard | NIST Alternate | **Pre-proposal** |

The key advantage: LNAT requires only bitwise XOR and array lookups.
It runs identically on an 8-bit microcontroller and a 64-bit server
without architectural modification.

---

## Repository Structure

```
lnat-pqc/
│
├── README.md                  ← you are here
├── SECURITY.md                ← responsible disclosure policy
├── LICENSE                    ← MIT License
├── pyproject.toml             ← packaging + pytest configuration
├── requirements.txt           ← legacy notes / optional deps
├── .gitignore
│
├── src/
│   └── lnat_pqc/              ← installable Python package
│       ├── __init__.py
│       ├── lnat_core.py       ← core automaton primitive
│       ├── lnat_kem.py        ← Key Encapsulation Mechanism (IND-CPA demo)
│       └── lnat_params.py     ← parameter sets (128/192/256)
│
├── tests/                     ← pytest suite
│   ├── test_kem.py            ← KEM correctness tests
│   ├── test_hardness.py       ← hard problem demonstration
│
├── paper/
│   └── LNAT_Research_Paper.docx  ← full research paper draft
│
├── docs/
│   ├── CONTRIBUTING.md        ← how to contribute
│   └── SECURITY.md            ← security notes for the research draft
│
└── .github/
    └── workflows/
        └── tests.yml          ← CI: run pytest on push / pull_request
```

### Planned / not yet implemented

- `src/lnat_sign.py` (signature prototype)
- `tests/test_vectors.py` and `tests/vectors/` known-answer test vectors
- `benchmarks/` benchmarking scripts
- `reference/` standalone hard problem demo scripts

---

## Quick Start

```bash
git clone https://github.com/muhammadsohaimmuqtada/lnat-pqc
cd lnat-pqc
python -m pip install -e .[test]
pytest
```

```python
from lnat_pqc.lnat_kem import LNATKEM
from lnat_pqc.lnat_params import LNAT128
```

---

## The Algorithm — Plain English

### KeyGen
```
1. Generate a random 32-byte seed (your private key)
2. Derive a secret transition table from the seed using AES
3. Pick a random starting state q0
4. Generate a random input sequence A
5. Run the machine through A, collect outputs Y
6. Public key = (A, Y)   Private key = seed
```

### Encap (Encrypt a session key)
```
1. Generate random session key r
2. Mix r into the public outputs Y using XOR
3. Send the result as ciphertext
```

### Decap (Decrypt)
```
1. Use seed to rerun the machine from q0 through A
2. Recover the same Y
3. XOR Y away from ciphertext
4. Recover r using error correction
```

---

## Parameter Sets

| Level | n | m | T | Classical security | Quantum security |
|---|---|---|---|---|---|
| LNAT-128 | 128 | 8 | 512 | 128 bits | 64 bits |
| LNAT-192 | 192 | 8 | 768 | 192 bits | 96 bits |
| LNAT-256 | 256 | 16 | 1024 | 256 bits | 128 bits |

---

## Known Open Problems

These are acknowledged weaknesses under active research:

1. **Table generation speed** — using lazy PRF tree to reduce
   AES calls from O(T) to O(log n)
2. **Formal security proof** — reduction to noisy MQ is sketched,
   full proof is in progress
3. **Side channel resistance** — bitsliced implementation needed
   for constant-time table lookup
4. **Signature scheme** — LNAT-Sign is a skeleton, abort
   probability analysis not yet complete

See [docs/SECURITY.md](docs/SECURITY.md) for full details.

---

## Contributing

We actively want people to:

- **Try to break it** — cryptanalysis attempts are the most valuable contribution
- **Implement it** — independent implementations in C, Rust, Go
- **Formalize it** — help complete the security reduction proof
- **Benchmark it** — real hardware measurements on embedded targets

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for details.

---

## Research Paper

The full research paper is in [paper/LNAT_Research_Paper.docx](paper/LNAT_Research_Paper.docx).

It covers:
- Formal problem definition
- Complete KEM and signature construction
- Security analysis against classical and quantum attackers
- Parameter justification
- Comparison to ML-KEM and Picnic

---

## Status

- [x] Hard problem defined
- [x] KEM construction sketched
- [ ] Sign construction sketched (planned)
- [x] Reference Python implementation
- [ ] Known answer tests
- [ ] Lazy PRF tree optimization
- [ ] BCH error correction integration
- [ ] Formal security proof
- [ ] C reference implementation
- [ ] Side channel analysis
- [ ] IACR ePrint submission
- [ ] External cryptographic review

---

## Citation

If you use this work, please cite:

```bibtex
@misc{lnat2026,
  title  = {LNAT: Learning Noisy Automata Transitions,
             a Post-Quantum Cryptographic Primitive},
  year   = {2026},
  note   = {Pre-publication draft. \url{https://github.com/muhammadsohaimmuqtada/lnat-pqc}}
}
```

---

## License

MIT License. See [LICENSE](LICENSE).

---

## Disclaimer

This is a research prototype. The security of LNAT has not been
verified by external cryptographers. It should not be used to protect
real data under any circumstances until it has undergone years of
public scrutiny and formal analysis.
