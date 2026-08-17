# LNAT-CODE-KEM-1 public decapsulation attack

## Status

The default research `LNAT-CODE-KEM-1` profile is intentionally attackable through the same public random-code decoding relation as KEM-0.

KEM-1 improves transport efficiency only. It does not change the asymmetric security boundary.

## Attack

Given only the KEM-1 public key and ciphertext:

1. run Prange-style information-set decoding on the public noisy-code instance;
2. recover the sparse code witness;
3. convert every segmented ciphertext word into the receiver inner-product observation;
4. maximum-likelihood decode each 8-bit outer-code block;
5. reconstruct the full encapsulated seed;
6. verify the public confirmation tag; and
7. derive the exact 32-byte session key.

The LNAT master seed is never recovered or used by the attacker.

Executable regression:

```bash
python attacks/code_kem1_public_decapsulation.py
```

Unit regression:

```bash
python -m unittest tests.test_code_kem1_attacks -v
```

## Interpretation

A smaller ciphertext is an engineering improvement, not a security improvement. Any future KEM-1 parameter work must still be evaluated against modern decoding/ISD attacks on the public code instance.
