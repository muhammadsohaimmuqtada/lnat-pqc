# LNAT-MLKEM768-HYBRID-v1

## Purpose

This profile gives the repository a complete KeyGen/Encap/Decap workflow while standalone LNAT research continues. It does **not** claim that LNAT itself provides public-key security.

## Security boundary

ML-KEM-768 supplies public-key encapsulation. LNAT-EXP2 is used only after ML-KEM has established a 32-byte shared secret.

The final key derivation keeps the raw ML-KEM shared secret as a direct SHAKE256 input. LNAT output is additional deterministic transcript material and is never the sole secret input.

Therefore:

- breaking standalone LNAT is not intended to reveal the final key by itself;
- the profile does not claim security stronger than ML-KEM-768;
- this repository does not contain a formal composition proof;
- this is a research integration profile, not production guidance.

## Backend

The default backend uses `cryptography>=47` and ML-KEM-768.

## Key generation

1. Generate an ML-KEM-768 keypair.
2. Serialize the 64-byte private seed and 1184-byte public key.
3. Generate a 32-byte public context seed.
4. Return versioned hybrid wrappers.

## Encapsulation

1. Run ML-KEM-768 encapsulation to obtain `(ss_mlkem, ct_mlkem)`.
2. Hash the complete hybrid public key.
3. Derive a secret LNAT seed from `ss_mlkem`, the public-key digest, and ciphertext.
4. Derive deterministic LNAT nonce/input-seed values from public context.
5. Run LNAT-EXP2 noiselessly so both parties obtain the same transcript.
6. Derive the final key from:

```text
profile || ss_mlkem || pk_digest || ct_mlkem || lnat_transcript
```

The direct inclusion of `ss_mlkem` is intentional.

## Decapsulation

1. Verify wrapper/context consistency.
2. Run ML-KEM-768 decapsulation.
3. Recompute the deterministic LNAT transcript.
4. Run the same final SHAKE256 extraction.

## Serialization

Public keys, private keys, and ciphertexts use explicit magic/version values; public/private objects embed the LNAT profile name. Parsers reject malformed lengths and mismatched profiles/context.

## What this profile demonstrates

It demonstrates a complete PQC-backed integration, deterministic LNAT post-processing, serialization, tests, and CI. It does not prove a new PQ hardness assumption or standalone LNAT KEM.
