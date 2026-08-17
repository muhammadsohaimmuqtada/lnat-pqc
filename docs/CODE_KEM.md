# LNAT-CODE-KEM-0

## Status

`LNAT-CODE-KEM-0` is a **functional research KEM harness**, not a secure or standardized KEM.

It exists to complete the KeyGen/Encap/Decap mechanics around `LNAT-CODE-BRIDGE-0` so that correctness, ciphertext cost, failure behavior, attacks, and future transforms can be measured end-to-end.

The security boundary remains the public random-code decoding problem. LNAT derives the receiver's sparse decoding witness; it does not currently supply an independent public-key hardness assumption.

The repository's operational PQC path remains `LNAT-MLKEM768-HYBRID-v1`.

## Key generation

1. Generate the random-code bridge public key.
2. Generate a compact LNAT seed.
3. Run the LNAT transition schedule and derive the sparse code witness.
4. Publish the noisy-code instance plus public LNAT schedule data.
5. Keep the LNAT seed as the receiver secret.

## Encapsulation

1. Sample a random seed `r`.
2. Encrypt every bit of `r` with the public random-code encryption mechanism.
3. Hash the public-key context.
4. Compute a confirmation tag over `r`, the public context, and the complete ciphertext body.
5. Derive the 32-byte session key with SHAKE256 from `r`, public context, ciphertext body, and confirmation tag.

The sender needs only the public key.

## Decapsulation

1. Re-run LNAT from the receiver seed and public schedule to regenerate the sparse code witness.
2. Decrypt every encrypted bit and reconstruct `r`.
3. Recompute the confirmation tag.
4. Reject if confirmation fails.
5. Derive the same 32-byte session key.

## What the confirmation tag does and does not mean

The confirmation tag catches ordinary decoding failures, wrong secret keys, and ciphertext modification in the reference implementation.

It is **not** a Fujisaki-Okamoto transform and there is no IND-CCA proof for this construction. Rejection behavior may itself be security-relevant. The module must not be described as CCA-secure.

## Efficiency

The reference construction encrypts the random seed bit-by-bit and is intentionally inefficient. Ciphertext size is approximately:

```text
encapsulated_seed_bits * repetitions * ceil(n / 8) + tag_bytes
```

before any future compression or structural optimization.

This makes ciphertext growth visible instead of hiding it behind an unrealistic size claim.

## Required research before any serious candidate

- replace toy bridge parameters with profiles that survive concrete modern ISD estimates;
- measure full encapsulation/decapsulation failure probability, not just individual bit failure;
- investigate multi-bit/codeword encryption instead of bit-by-bit repetition;
- analyze confirmation/rejection behavior;
- define a formal PKE/KEM security game;
- obtain independent cryptanalysis;
- identify whether LNAT contributes any hardness beyond deterministic witness generation.
