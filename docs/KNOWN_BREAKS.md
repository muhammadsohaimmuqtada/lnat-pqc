# Known Breaks

## KEM-v1: complete public recovery

**Status:** complete confidentiality break.

The archived KEM-v1 chose random message bits `r`, repetition-encoded them, extended the public trace `Y`, and produced:

```text
ct = Encode(r) XOR Extend(pk.Y)
K  = H(r)
```

But `pk.Y` is public. Therefore any observer computes:

```text
Encode(r) = ct XOR Extend(pk.Y)
r         = Decode(Encode(r))
K         = H(r)
```

The attack requires no private key, no state recovery, no transition-table reconstruction, and no cryptanalysis of HMAC-SHA256.

A runnable reproduction is provided in:

```text
attacks/public_recovery_v1.py
```

and the regression test is:

```text
tests/test_broken_kem.py
```

This break invalidates any IND-CPA or IND-CCA claim for KEM-v1.

## Security-level claims from state size

Earlier versions equated state size `n` with classical security and `n/2` with quantum security. No reduction or attack analysis justified those values. These claims have been removed.

## Full-table counting argument

Earlier analysis counted the number of arbitrary transition tables. The implementation instead selects a transition function from a seed-derived PRF family. Counting all possible arbitrary tables does not establish the security of the implemented family and is no longer used as a security argument.

## Failed-attacker demonstrations

A previous `test_hardness.py` constructed one deliberately weak guessed-state attacker and interpreted its failure as evidence of hardness. Failure of a single toy attack is not a hardness result. That file has been removed from the test suite.
