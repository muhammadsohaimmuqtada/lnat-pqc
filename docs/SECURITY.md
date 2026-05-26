# LNAT Security Analysis

This document covers known attacks, open problems,
and the current state of the security argument.

---

## The LNAT Hard Problem

**Given:** T pairs (a_t, y_t) where:
- a_t is a public input (known)
- y_t = λ(δ(q_{t-1}, a_t)) ⊕ e_t is a noisy output
- δ is the secret transition function
- e_t is a noise bit flipped with probability η

**Goal:** Recover δ (or equivalently, distinguish
the sequence from random).

---

## Known Attacks and Why They Fail

### Classical Attacks

**Exhaustive search**
- Key space: 2^(n × 2^(n+m)) possible transition tables
- At n=128: physically impossible
- Status: NOT A THREAT

**Table reconstruction from observations**
- Each observation (a_t, y_t) gives a noisy constraint on
  λ(δ(q_{t-1}, a_t)) — but q_{t-1} is unknown to the attacker
- Without knowing the state sequence, observations cannot be
  indexed into the table
- Even T=2^128 observations would not cover 2^136 table entries
- Status: NOT A THREAT

**Gaussian elimination / linear algebra**
- Applies only if δ is linear
- LNAT uses uniformly random δ with no algebraic structure
- Status: NOT APPLICABLE

**Algebraic attacks (XL, Groebner bases)**
- These attack systems of polynomial equations
- LNAT's transition table has no polynomial structure
- Status: NOT APPLICABLE

**Correlation attacks (on LFSRs)**
- Apply when output function has low algebraic degree
- LNAT uses random output function with degree n
- Status: NOT APPLICABLE

**SAT solver attacks**
- Could encode LNAT recovery as a SAT/MaxSAT instance
- At n=128: formula has 2^136 variables — beyond all known solvers
- At small n (n≤16): SAT solvers CAN recover the table
- For n≤20, empirical testing recommended
- Status: RELEVANT ONLY AT VERY SMALL PARAMETERS

### Quantum Attacks

**Shor's algorithm**
- Requires hidden subgroup structure in an abelian group
- LNAT has no group structure
- Status: NOT APPLICABLE

**Quantum walks (Szegedy, Magniez et al.)**
- Speed up graph search problems
- LNAT recovery is a function learning problem, not graph search
- Status: NOT APPLICABLE

**Grover's algorithm**
- Searches unstructured space in O(√N) time
- Applied to LNAT key space: O(2^(n/2)) quantum operations
- At n=256: O(2^128) — computationally infeasible
- Status: PROVIDES QUADRATIC SPEEDUP — MITIGATED BY DOUBLING n

**BKZ / quantum lattice reduction**
- Specific to lattice problems
- LNAT has no lattice structure
- Status: NOT APPLICABLE

---

## Current Security Argument

**Theorem (informal):**
LNAT-KEM is IND-CPA secure if the LNAT problem is hard.

**Proof sketch:**
Suppose adversary A breaks LNAT-KEM with non-negligible
advantage ε. Construct reduction R:

1. R receives LNAT challenge (seed_A, Y)
2. R sets (seed_A, Y) as the public key
3. R runs A on this public key
4. A produces a ciphertext guess
5. R uses A's output to distinguish LNAT from random

If A's advantage is ε, R's advantage is ε/2.
This contradicts the hardness of LNAT.

**Status:** This is a sketch. Full formal proof is open.

**IND-CCA2:**
Applying the Fujisaki-Okamoto transform to the IND-CPA
scheme gives IND-CCA2 in the random oracle model.
FO transform security is standard — the only gap is
completing the IND-CPA proof above.

---

## Open Security Problems

1. **Complete the IND-CPA proof**
   The reduction sketch above needs to be formalized
   with exact security parameters and error analysis.

2. **Direct reduction from LWE or LPN**
   Current reduction goes LNAT → noisy MQ.
   A reduction from LNAT → LPN would provide a stronger
   hardness argument connecting to well-studied problems.

3. **Tightness of the reduction**
   Even after completing the proof, the reduction may
   have polynomial security loss. Tight reductions are
   preferable.

4. **Side channel analysis**
   The reference implementation uses standard array
   indexing which is vulnerable to cache timing attacks.
   A constant-time (bitsliced) implementation is required
   for deployment. This is a known open problem.

5. **Distinguishing attacks at small parameters**
   Empirical testing at n=8, 12, 16, 20 with SAT solvers
   and constraint propagation would give concrete data
   on where the practical security threshold lies.

---

## Parameters and Security Levels

| Level    | n   | Quantum security | NIST level |
|----------|-----|------------------|------------|
| LNAT-128 | 128 | 64 bits          | Level 1    |
| LNAT-192 | 192 | 96 bits          | Level 3    |
| LNAT-256 | 256 | 128 bits         | Level 5    |

Note: NIST Level 5 requires 128-bit quantum security.
LNAT-256 meets this threshold under Grover bounds.

---

## What Would Break LNAT

1. A quantum algorithm faster than Grover for unstructured search
   (would affect ALL post-quantum schemes)

2. A polynomial-time algorithm for noisy multivariate boolean
   equation solving (would also break all MQ-based schemes)

3. An unexpected algebraic structure in HMAC-SHA256 used as PRF
   that allows the transition table to be partially reconstructed

4. A mathematical insight specific to finite automaton inversion
   that has no analogue in existing cryptanalysis

None of these are currently known. All would be significant
independent results in computational complexity theory.
