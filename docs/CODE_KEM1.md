# LNAT-CODE-KEM-1

## Status

`LNAT-CODE-KEM-1` is the second functional research KEM harness built on the random-code/LNAT bridge. It is **not** a secure or standardized KEM and does not create a standalone LNAT hardness assumption.

The operational PQC path remains `LNAT-MLKEM768-HYBRID-v1`.

## What changed from KEM-0

`LNAT-CODE-KEM-0` encrypts every encapsulated seed bit independently with many repeated code-PKE words. That is simple but extremely large.

KEM-1 instead:

1. splits the random encapsulated seed into bytes;
2. assigns one small public binary outer code to each byte;
3. transmits one code-PKE word per outer-code symbol;
4. reconstructs the LNAT-derived sparse receiver witness once;
5. converts each ciphertext block to receiver observation bits; and
6. maximum-likelihood decodes each 8-bit block independently.

A 128-bit seed is therefore decoded as sixteen 256-candidate ML problems instead of one impossible `2^128` message search.

## Default research profile

The default KEM-1 research profile uses:

```text
encapsulated seed       = 16 bytes / 128 bits
outer blocks            = 16
message bits per block  = 8
channel uses per block  = 128
code-PKE n              = 128
code-PKE k              = 64
secret witness weight   = 4
encryption error weight = 1
confirmation tag        = 16 bytes
```

The induced receiver channel has `q = 4/128 = 1/32`, matching the reduced outer-code experiments.

## Size

KEM-1 reference ciphertext payload:

```text
16 blocks * 128 words/block * 16 bytes/word + 16-byte tag
= 32,784 bytes
```

The KEM-0 repetition reference with the same 128-bit seed and default `128` repetitions is:

```text
128 bits * 128 words/bit * 16 bytes/word + 16-byte tag
= 262,160 bytes
```

So KEM-1 reduces the reference ciphertext by almost **8x** while retaining a decoder whose work grows linearly in the number of byte blocks.

This is still far larger than standardized KEM ciphertexts and is not an efficiency claim against ML-KEM.

## Confirmation and KDF

KEM-1 retains the research confirmation-tag pattern:

- hash the full public context, including all outer-code generator rows;
- bind the recovered random seed, public-context digest, and ciphertext body into the tag;
- reject if confirmation fails; and
- derive a 32-byte session key with SHAKE256 from the same context.

This detects decoding/tampering failures in the reference implementation. It is **not** a Fujisaki-Okamoto transform and there is no IND-CCA proof.

## Security boundary

KEM-1 does not change the public attack target. The attacker can still target the sparse random-code witness directly with decoding/ISD techniques. LNAT currently derives that witness but does not add a proven independent hardness assumption.

The KEM-0 public-decapsulation attack therefore defines the expected attack direction for KEM-1 as well: recover the public code witness, decode the outer blocks, verify confirmation, and derive the session key.

## Run

```bash
python experiments/lnat_code_kem1_probe.py --trials 2
```

## Next research tasks

- add the corresponding public-decapsulation attack regression;
- measure block and whole-seed failure over much larger Monte Carlo samples;
- replace random byte-sized ML codes with a structured scalable channel code;
- apply modern ISD work estimates to non-toy public-code parameters;
- determine whether LNAT can contribute a public relation or reduction rather than only deterministic witness generation.
