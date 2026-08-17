# LNAT-CODE-KEM-0

## Status

`LNAT-CODE-KEM-0` is a **functional research KEM harness**, not a secure or standardized KEM.

It exists to complete the KeyGen/Encap/Decap mechanics around `LNAT-CODE-BRIDGE-0` so correctness, ciphertext cost, failure behavior, attacks, and future transforms can be measured end-to-end.

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
2. Encrypt every bit of `r` with the public random-code mechanism.
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

## Full-KEM correctness

Correctness is screened at the complete encapsulated-seed level, not merely per encrypted bit. The parameter audit reports both a modeled independent-bit seed-failure probability and a conservative union bound over all encapsulated bits.

## Efficiency and channel-capacity gap

The current reference construction encrypts every seed bit by repeating the binary hypothesis experiment many times. Its ciphertext size is approximately

```text
encapsulated_seed_bits * repetitions * ceil(n / 8) + tag_bytes.
```

For each public-code word, the receiver observes a binary asymmetric channel:

```text
P(Z=1 | encoded bit 0) = q
P(Z=1 | encoded bit 1) = 1/2
```

where `q` is the odd support-intersection probability. `src/code_channel_audit.py` computes the Shannon capacity of this channel and compares the repetition construction with a capacity-only lower bound.

For the current necessary-screening regression point `(n=256,k=128,w=30,error_weight=1,repetitions=233)` carrying a 128-bit seed:

```text
channel capacity              ~= 0.131486 bits/use
repetition channel uses        = 29,824
capacity-only lower-bound uses = 974
repetition ciphertext          = 954,384 bytes
capacity-only byte floor       = 31,184 bytes
repetition overhead            ~= 30.6x
```

The ~31 KB figure is **not an achievable ciphertext claim**. It ignores finite-blocklength reliability overhead and coding structure. It only proves that independent per-bit repetition leaves a large efficiency gap worth researching.

Tool:

```bash
python experiments/code_channel_audit.py
```

## Required research before any serious candidate

- replace toy bridge parameters with profiles that survive concrete modern ISD estimates;
- retain full-KEM rather than per-bit failure analysis;
- replace independent bit repetition with a justified multi-bit/channel-coding construction;
- measure finite-blocklength correctness and ciphertext size of that construction;
- analyze confirmation/rejection behavior;
- define a formal PKE/KEM security game;
- obtain independent cryptanalysis;
- identify whether LNAT contributes any hardness beyond deterministic witness generation.
