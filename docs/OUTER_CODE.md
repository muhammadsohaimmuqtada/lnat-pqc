# Multi-bit outer-code experiment

## Purpose

The current `LNAT-CODE-KEM-0` reference encrypts each encapsulated seed bit independently with many repeated code-PKE words. The channel-capacity audit shows that this leaves a large efficiency gap.

`src/code_outer_channel.py` tests one concrete way to recover some of that gap on deliberately small parameters:

1. encode several message bits with a public binary linear outer code;
2. transmit one random-code PKE word per outer-code symbol;
3. let the receiver reduce each word to its secret inner-product observation; and
4. maximum-likelihood decode the complete outer-code message using the known asymmetric channel law.

## Current reduced experiment

The regression uses:

```text
message bits       = 8
outer channel uses = 128
code-PKE n         = 64
secret weight      = 2
encryption error   = 1
```

The old repetition fixture uses `8 * 96 = 768` channel words, while the outer-code experiment uses 128 words, a **6x word-count reduction**:

```text
repetition payload = 6144 bytes
outer-code payload = 1024 bytes
```

before confirmation/tag framing.

## Channel-law regression

For the reduced `(n=64,w=2,error_weight=1)` receiver channel,

```text
q = P(Y=1 | X=0) = 2/64 = 1/32
P(Y=1 | X=1) = 1/2.
```

The capacity implementation is regression-tested at:

```text
C ~= 0.238541357819 bits/use.
```

This explicit value prevents stale probe output from being mistaken for the current channel model.

## Finite-blocklength sweep

`src/code_outer_sim.py` directly simulates the exact receiver observation law without constructing the much larger random-code ciphertext words. The full bridge path is still tested separately.

Run:

```bash
python experiments/outer_code_sweep.py \
  --message-bits 8 \
  --lengths 48,64,80,96,112,128 \
  --trials 64 \
  --q 0.03125
```

The output reports code rate, fraction of Shannon capacity, and empirical ML-decoding failure for each block length. These are deterministic finite samples for engineering guidance, not reliability proofs.

## Why this is not the final KEM code

The decoder enumerates all `2^k` messages and is deliberately capped at 16 message bits. It is a proof-of-concept that multi-bit coding can exploit the channel better than independent repetition, not a scalable 128-bit encapsulation design.

A serious replacement needs a structured decoder suitable for the asymmetric channel, such as a carefully analyzed polar/LDPC-style construction, plus much larger finite-blocklength failure measurements.

## Security boundary

Changing the channel code changes efficiency and correctness only. It does not change the public random-code decoding security boundary and does not create a standalone LNAT hardness assumption.

## Run the full bridge probe

```bash
python experiments/outer_code_probe.py --trials 32 --channel-uses 128
```
