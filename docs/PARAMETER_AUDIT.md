# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator or to `LNAT-CODE-BRIDGE-0`.

Before a code-based research profile is even worth deeper cryptanalysis, two necessary checks can be computed exactly.

## 1. Trivial sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are

```text
C(n,w)
```

possible supports. Therefore an attacker can always enumerate at most that many candidates. The quantity

```text
log2(C(n,w))
```

is a **ceiling against this trivial attack**, not a security estimate. Information-set decoding or other decoding attacks may be substantially cheaper.

A 256-bit LNAT master seed cannot provide 256 bits of security if it deterministically maps into a public hidden witness whose entire support has far fewer than `2^256` possibilities.

## 2. Exact toy correctness model

For the current Alekhnovich-style comparator, an encryption of zero has the form

```text
c_perp + e'
```

where `c_perp` is orthogonal to the secret sparse witness `e`. The decryption inner product is therefore controlled by the parity of the intersection between the supports of `e` and `e'`.

For fixed weights `w` and `t`, the probability of an odd intersection is computed exactly with the hypergeometric distribution. Given the repetition count and decision threshold, the bit-0 and bit-1 decryption failure probabilities then follow from exact binomial tails.

This is a correctness calculation for the reference model. It does not prove security.

## Tooling

```bash
python experiments/code_profile_audit.py
python experiments/code_profile_audit.py --n 256 --k 128 --secret-weight 30 --error-weight 8 --trivial-floor-bits 128
```

The second command only asks whether naive exact-weight enumeration reaches the requested work-factor floor. Passing that check is necessary but not sufficient for any security claim.

## Rule for future profiles

No future bridge profile should be presented as a serious candidate until it has, at minimum:

1. an explicit trivial witness-space audit;
2. an exact or conservative correctness/failure analysis;
3. concrete decoding/ISD attack estimates;
4. attack implementations on reduced parameters;
5. a clearly stated security assumption or reduction target.
