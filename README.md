# LNAT-PQC Research

**Learning Noisy Automata Transitions — experimental primitive, cryptanalysis harness, and operational ML-KEM integration**

LNAT studies secret-seeded noisy state-transition processes as a cryptographic research object. The repository separates components that must not be confused:

| Component | Status | Purpose |
|---|---|---|
| `LNAT-EXP2` | experimental | standalone noisy-automaton primitive for analysis |
| archived `LNAT KEM-v1` | **broken** | reproducible negative result |
| `LNAT-CODE-*` | research comparator; **not a PQ-secure candidate** | explores a random-code asymmetric boundary and attack methodology |
| `LNAT-MLKEM768-HYBRID-v1` | operational research profile | complete PQC-backed KeyGen/Encap/Decap integration |

> **Security boundary:** standalone LNAT has no established security level. The operational hybrid uses ML-KEM-768 for public-key encapsulation and keeps the ML-KEM shared secret as a direct input to the final SHAKE256 extraction. LNAT is additional deterministic post-processing, not an independently proven source of post-quantum security.

The random-code `LNAT-CODE-*` experiments are also not a substitute for that boundary. Their current `(1064,532,w=117)` point crosses the repository's pinned **classical** modern-ISD screen, but a transparent Groverized-Prange baseline reduces the search-iteration exponent to about `63.68`. The point is therefore retained only as a classical-screen regression, not as a post-quantum parameter recommendation. Stronger quantum ISD is still an open cryptanalytic requirement.

## LNAT-EXP2

EXP1 exposed the least-significant bit of every hidden state. EXP2 instead defines:

```text
q_0 = Q0_s(nonce)
q_t = Delta_s(q_{t-1}, a_t)
z_t = LSB(PRF_s(D_OBS || t || q_t))
y_t = z_t XOR e_t
```

`Q0`, `DELTA`, `OBS`, and input expansion are domain-separated. This removes an avoidable fixed-coordinate observation; it is **not** a security proof.

See [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).

## Operational hybrid

```python
from lnat_hybrid_kem import LNATMLKEM768

kem = LNATMLKEM768()
pk, sk = kem.keygen()
ct, sender_key = kem.encap(pk)
receiver_key = kem.decap(sk, pk, ct)
assert sender_key == receiver_key
```

The hybrid uses ML-KEM-768 to establish the secret, deterministically derives an LNAT-EXP2 transcript from that secret and public context, then derives the final 32-byte key from **both** the ML-KEM secret and the LNAT transcript.

See [`docs/HYBRID_KEM.md`](docs/HYBRID_KEM.md).

## Install

Core research primitive:

```bash
git clone https://github.com/muhammadsohaimmuqtada/lnat-pqc.git
cd lnat-pqc
python -m pip install -e .
```

Operational ML-KEM hybrid and CLI:

```bash
python -m pip install -e ".[pqc]"
lnat-pqc selftest
```

The ML-KEM Python backend requires `cryptography>=47`.

Modern classical syndrome-decoding estimator:

```bash
python -m pip install -e ".[estimator]"
```

### End-to-end CLI

```bash
lnat-pqc keygen \
  --public-out public.lnat \
  --private-out private.lnat

lnat-pqc encap \
  --public public.lnat \
  --ciphertext-out ciphertext.lnat \
  --key-out sender.key

lnat-pqc decap \
  --public public.lnat \
  --private private.lnat \
  --ciphertext ciphertext.lnat \
  --key-out receiver.key

cmp sender.key receiver.key
```

The CLI does not print shared keys by default. Private keys and derived shared-key files are written with mode `0600` on POSIX systems, outputs are written atomically, and existing files are not overwritten unless `--force` is supplied.

## Tests and attacks

```bash
python -m unittest discover -s tests -v
python attacks/public_recovery_v1.py
python attacks/exhaustive_seed_recovery.py --seed-bits 8 --traces 3 --noise 0.05
python attacks/statistical_probe.py --samples 32
python attacks/markov_predictor.py --train 64 --test 32 -k 4
python experiments/quantum_isd_probe.py \
  --n 1064 --k 532 --weight 117 \
  --iteration-floor-bits 128 --expect reject
python benchmarks/bench.py --rounds 10 --hybrid
```

CI runs Python 3.11, 3.12, and 3.13, installs the real ML-KEM backend, runs unit/integration tests, reproduces the archived KEM-v1 break, runs code-decoding attack regressions, cross-checks the pinned classical syndrome-decoding estimator, and requires the classical-only `(1064,532,w=117)` frontier to be rejected by the quantum-search baseline.

## Attack-first research

Current tooling includes:

- complete public recovery of archived KEM-v1;
- exhaustive minimum-Hamming-distance seed recovery for deliberately tiny seed spaces;
- multi-trace scoring under noise;
- monobit and lag-1 trace statistics;
- held-out Markov next-bit prediction;
- executable Prange, Lee-Brickell, and Stern code-decoding baselines;
- pinned modern classical syndrome-decoding estimates;
- transparent Groverized-Prange/support-enumeration quantum-search screening;
- machine-readable parameter sweeps;
- deterministic known-answer vectors.

See [`docs/GAMES.md`](docs/GAMES.md), [`docs/PARAMETER_AUDIT.md`](docs/PARAMETER_AUDIT.md), and [`docs/RESEARCH_ROADMAP.md`](docs/RESEARCH_ROADMAP.md).

## Repository layout

```text
lnat-pqc/
├── src/
│   ├── lnat_core.py
│   ├── lnat_params.py
│   ├── lnat_analysis.py
│   ├── lnat_hybrid_kem.py
│   ├── code_sd_estimator.py
│   ├── code_modern_frontier.py
│   ├── code_quantum_isd.py
│   ├── lnat_cli.py
│   └── lnat_kem.py
├── attacks/
│   ├── public_recovery_v1.py
│   ├── exhaustive_seed_recovery.py
│   ├── statistical_probe.py
│   └── markov_predictor.py
├── experiments/
│   ├── parameter_sweep.py
│   ├── modern_frontier_probe.py
│   └── quantum_isd_probe.py
├── benchmarks/bench.py
├── tests/
└── docs/
```

## Research status

Completed:

- [x] KEM-v1 break reproduced and quarantined
- [x] unsupported NIST/security-level claims removed
- [x] EXP2 primitive specified and implemented
- [x] keyed observation function and full domain separation
- [x] deterministic KAT
- [x] toy exhaustive-recovery harness
- [x] statistical/prediction probes
- [x] operational ML-KEM-768 hybrid KeyGen/Encap/Decap
- [x] versioned serialization and context binding
- [x] operational CLI with protected key-file handling
- [x] executable code-decoding attack baselines
- [x] pinned modern classical ISD screening
- [x] classical-only frontier rejected under a quantum-search baseline
- [x] Python 3.11–3.13 CI

Open standalone-LNAT/code research:

- [ ] identify a defensible LNAT-native public-key trapdoor/asymmetric relation
- [ ] finite best-known quantum-ISD/resource estimate for any random-code candidate
- [ ] stronger distinguishers and time-memory attacks
- [ ] concrete classical and quantum attack-cost models for any proposed large profile
- [ ] independent cryptanalysis
- [ ] formal reduction/assumption if one can actually be established
- [ ] constant-time implementation before any deployment discussion

## Research paper

`paper/LNAT_Research_Paper.docx` predates the cryptanalytic reset and EXP2. It is historical material, not the current authoritative specification.

## License

MIT.
