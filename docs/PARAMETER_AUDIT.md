# Code-profile parameter audit

This repository does not assign a security level to the random-code comparator or to `LNAT-CODE-BRIDGE-0`.

Before a code-based research profile is even worth deeper cryptanalysis, several necessary checks must be reported separately.

## 1. Full sparse-witness enumeration ceiling

For an exact-weight hidden witness of length `n` and weight `w`, there are

```text
C(n,w)
```

possible supports. Therefore an attacker can always enumerate at most that many candidates. The quantity

```text
log2(C(n,w))
```

is only a ceiling against this basic attack.

A 256-bit LNAT master seed cannot provide 256 bits of security if it deterministically maps into a public hidden witness whose entire support has far fewer than `2^256` possibilities.

## 2. Prange information-set decoding baseline

Full enumeration is not the strongest obvious public attack. For a binary `[n,k]` code and an error of weight `w`, the basic Prange information-set strategy repeatedly chooses a size-`k` information set that is assumed to be error-free. Its combinatorial success probability corresponds to an expected information-set count of

```text
C(n,w) / C(n-k,w)
```

when `w <= n-k`.

The repository reports

```text
log2(expected information-set trials)
```

separately from the full witness-space size. This is **not a total operation count**: each trial still requires linear algebra, and modern information-set decoding variants can improve on basic Prange.

For the deliberately tiny `(n=64,k=32,w=2)` bridge fixture, this model is only a few expected information-set trials even though the full support contains 2016 witnesses.

`src/code_attacks.py` includes an actual Prange-style decoder for reduced parameters so the model is checked by executable attacks rather than documentation alone.

## 3. Exact reference correctness model

For the current Alekhnovich-style comparator, an encryption of zero has the form

```text
c_perp + e'
```

where `c_perp` is orthogonal to the secret sparse witness `e`. The decryption inner product is therefore controlled by the parity of the intersection between the supports of `e` and `e'`.

For fixed weights `w` and `t`, the probability of an odd intersection is computed exactly with the hypergeometric distribution. Given the repetition count and decision threshold, the bit-0 and bit-1 decryption failure probabilities then follow from binomial tails.

The frontier tooling chooses the decision cutoff that minimizes the larger of those two bit-failure probabilities, then finds the smallest repetition count meeting a requested failure ceiling.

This is a correctness calculation for the reference model. It does not prove security.

## 4. Necessary parameter frontier

`experiments/code_parameter_frontier.py` combines the two filters above without turning them into a security claim.

For a requested basic-Prange **trial floor**, it finds the smallest sparse witness weight that reaches that combinatorial trial count. It then chooses the smallest repetition count and best decision cutoff meeting a requested modeled correctness-failure ceiling.

Example:

```bash
python experiments/code_parameter_frontier.py \
  --n 256 --k 128 \
  --prange-trial-bits 32 \
  --error-weight 1 \
  --failure-ceiling 1e-9
```

The current regression point is approximately:

```text
n = 256
k = 128
secret weight = 30
basic-Prange expected trial bits >= 32
repetitions = 183
cutoff ones = 52
modeled worst bit failure <= 1e-9
```

This means only that the point survives those **two necessary filters**. It is not a 32-bit security claim, because the Prange number omits per-trial linear-algebra cost and stronger ISD methods may be cheaper. It is also not a deployment recommendation.

A grid can be generated with:

```bash
python experiments/code_parameter_frontier.py --grid
```

## Tooling

```bash
python experiments/code_profile_audit.py
python experiments/code_profile_audit.py \
  --n 256 --k 128 \
  --secret-weight 30 --error-weight 1 \
  --trivial-floor-bits 128 \
  --prange-trial-floor-bits 32
python experiments/code_parameter_frontier.py --grid
```

The requested floors are analysis filters only. Passing them is not a security claim.

## Rule for future profiles

No future bridge profile should be presented as a serious candidate until it has, at minimum:

1. an explicit full witness-space audit;
2. basic Prange/ISD work estimates;
3. an exact or conservative correctness/failure analysis;
4. executable attacks on reduced parameters;
5. stronger ISD/BKW-style analysis where applicable;
6. a clearly stated security assumption or reduction target.
