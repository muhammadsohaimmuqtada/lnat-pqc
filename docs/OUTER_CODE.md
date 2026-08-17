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

The old repetition fixture uses:

```text
8 * 96 = 768 channel words
```

while the outer-code experiment uses 128 words, a **6x word-count reduction** and approximately:

```text
repetition payload = 6144 bytes
outer-code payload = 1024 bytes
```

before confirmation/tag framing.

## Why this is not the final KEM code

The decoder enumerates all `2^k` messages and is deliberately capped at 16 message bits. It is a proof-of-concept that multi-bit coding can exploit the channel better than independent repetition, not a scalable 128-bit encapsulation design.

A serious replacement needs a structured decoder suitable for the asymmetric channel, such as a carefully analyzed polar/LDPC-style construction, plus finite-blocklength failure measurements.

## Security boundary

Changing the channel code changes efficiency and correctness only. It does not change the public random-code decoding security boundary and does not create a standalone LNAT hardness assumption.

## Run

```bash
python experiments/outer_code_probe.py --trials 32 --channel-uses 128
```
