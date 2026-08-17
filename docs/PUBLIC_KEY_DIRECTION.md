# Standalone public-key direction

## Status

LNAT-EXP2 remains a secret-seeded state machine. It is not by itself a public-key encryption or KEM construction because an encapsulator cannot evaluate the secret transition/observation process without the secret seed.

The repository therefore keeps the operational `LNAT-MLKEM768-HYBRID-v1` path separate from research on a future LNAT-native asymmetric construction.

## Why a random-code reference is included

Alekhnovich's 2003 random-code encryption construction provides a clean example of a real public-key asymmetry based on noisy binary codes:

1. publish a random binary linear code `C` and a noisy codeword `c + e`;
2. retain the sparse error `e` as the secret key;
3. encrypt zero as a dual-code word plus a fresh sparse error;
4. encrypt one as a uniform word;
5. decrypt by taking inner products with `e` and distinguishing a strong zero bias from a uniform bit.

The key property is public evaluability with a hidden decoding witness: the sender only needs the public code instance, while the receiver has information (`e`) that makes the two ciphertext distributions distinguishable.

`src/code_pke_reference.py` implements this mechanism only as a deliberately small research comparator. It is not an LNAT construction, not a KEM, not CCA-secure, and its toy parameters make no security claim.

## What this tells us about LNAT

The current LNAT state chain has a measurable sequential effect: changing one input causes later hidden states and output bits to diverge, unlike a direct per-step PRF baseline. That is a useful primitive property, but it is not asymmetry.

A future standalone LNAT candidate must answer all of these questions before it is called a KEM:

- **Public evaluation:** what can an encapsulator compute from the public key without the LNAT secret seed?
- **Trapdoor/witness:** what information does only the decapsulator possess?
- **Hard problem:** what exact search/decision problem is exposed by the public key?
- **Correctness gap:** why can the secret holder reliably distinguish/recover while the public cannot?
- **Attack reduction:** does breaking the construction imply solving a clearly stated hard problem?
- **Failure probability:** what is the concrete decryption/decapsulation failure rate?

Simply publishing an LNAT trace, hashing it, or adding more noise does not create a trapdoor and must not be used as a replacement for these requirements.

## Current candidate strategy

The next research bridge should preserve a known public noisy-code relation as the asymmetry source while testing whether an LNAT-style sequential schedule can improve engineering or create a new analyzable relation. Any such candidate must initially be labelled as a comparator/experiment; security remains that of the underlying code problem until a new reduction exists.

## Primary research references

- Michael Alekhnovich, **More on Average Case vs Approximation Complexity**, FOCS 2003, DOI `10.1109/SFCS.2003.1238204`.
- Thomas Debris-Alazard, Philippe Gaborit, Romaric Neveu, Olivier Ruatta, **A Minrank-based Encryption Scheme à la Alekhnovich-Regev**, arXiv `2510.07584`, 2025. Its introduction restates the Alekhnovich public-key mechanism and explains the role of duality and the sparse-error inner product.
- Divesh Aggarwal, Rishav Gupta, Hai Hoang Nguyen, Kel Zin Tan, Prashant Nalini Vasudevan, **Towards Worst-case Hardness for Low-Noise LPN**, arXiv `2606.05834`, 2026. It studies the inverse-polynomial/`n^{-1/2}` noise regime relevant to Alekhnovich-style public-key encryption.
