# LNAT-PQC

**Learning Noisy Automata Transitions — experimental cryptography research**

LNAT studies whether a secret, seed-derived finite-state transition process observed through noisy traces yields a useful computational learning problem.

> **Security status:** no cryptographic security is claimed. The original KEM-v1 construction is publicly broken and is retained only as a reproducible negative result. Do not use this repository to protect real data.

## Research reset

The project has been reset to a defensible starting point:

- the LNAT primitive is specified independently of any KEM claim;
- parameter names describe experiment sizes, not security levels;
- the KEM-v1 confidentiality break is documented and tested;
- the historical KEM cannot be instantiated without an explicit `allow_broken=True` acknowledgement;
- tests separate implementation correctness from cryptanalytic evidence;
- security documentation does not claim NIST levels, IND-CPA, IND-CCA, or post-quantum strength.

## Primitive under study

For profile parameters `(n, m, T, eta)` and a secret seed `s`, LNAT-EXP1 uses:

```text
q_0 = Q0_s(nonce)
q_t = Delta_s(q_{t-1}, a_t)
z_t = LSB(q_t)
y_t = z_t XOR e_t,   e_t ~ Bernoulli(eta)
```

`Delta_s` and `Q0_s` are instantiated with domain-separated HMAC-SHA256 in the reference code. The public trace is generated from a public input-sequence seed and a public nonce.

This is a **research object**, not an accepted hardness assumption. See [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).

## Known break of KEM-v1

The archived KEM-v1 formed its ciphertext by XORing an encoded secret with `pk.Y`. Because `pk.Y` is public, anyone can remove the same mask and recover the encapsulated secret. No recovery of the automaton state or transition function is required.

See [`docs/KNOWN_BREAKS.md`](docs/KNOWN_BREAKS.md) and [`attacks/public_recovery_v1.py`](attacks/public_recovery_v1.py).

## Repository structure

```text
lnat-pqc/
├── src/
│   ├── lnat_core.py          # LNAT-EXP1 primitive
│   ├── lnat_params.py        # experimental parameter profiles
│   └── lnat_kem.py           # archived BROKEN KEM-v1
├── tests/
│   ├── test_core.py
│   └── test_broken_kem.py
├── attacks/
│   └── public_recovery_v1.py
├── experiments/
│   └── README.md
├── docs/
│   ├── SPECIFICATION.md
│   ├── SECURITY.md
│   ├── KNOWN_BREAKS.md
│   ├── RESEARCH_ROADMAP.md
│   └── CONTRIBUTING.md
├── paper/
│   ├── LNAT_Research_Paper.docx
│   └── README.md
├── pyproject.toml
└── README.md
```

## Run the reference checks

```bash
python -m unittest discover -s tests -v
python attacks/public_recovery_v1.py
python -m compileall -q src tests attacks
```

The attack script is expected to print `recovered =True`. That result confirms the repository is accurately reproducing the known KEM-v1 break.

## Current parameter profiles

The compatibility symbols `LNAT128`, `LNAT192`, and `LNAT256` remain in code, but their profile names are now:

- `LNAT-n128-exp1`
- `LNAT-n192-exp1`
- `LNAT-n256-exp1`

These labels refer to **state size only**. They do not mean 128/192/256-bit security and do not map to NIST security categories.

## What counts as progress now

The next milestone is not a faster KEM. It is evidence about the primitive:

1. define attack games precisely;
2. build exhaustive attacks for tiny `n`;
3. build SAT/SMT recovery models;
4. develop statistical distinguishers;
5. measure sample complexity and parameter sensitivity;
6. determine whether any asymmetric/trapdoor mechanism can be justified;
7. only then propose a KEM-v2 construction.

A future KEM must include an operation available to the public-key holder that creates a secret recoverable by the private-key holder but not by an observer with the same public data. KEM-v1 did not satisfy that requirement.

## Paper status

`paper/LNAT_Research_Paper.docx` predates this cryptanalytic reset. It is retained as historical research material and is **not authoritative** for the current construction or security status. See [`paper/README.md`](paper/README.md).

## Contributing

Reproducible attacks, counterexamples, formal definitions, independent implementations, and negative results are particularly valuable. See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

## License

MIT License.
