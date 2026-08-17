"""Public attacks against LNAT-CODE-KEM-0 research profiles.

The current KEM's asymmetric security boundary is the exposed random-code
syndrome-decoding instance.  If an attacker recovers the sparse code witness,
the LNAT master seed is unnecessary: the attacker can decrypt the encapsulated
seed, verify the public confirmation tag, and derive the exact session key.

This module makes that dependency executable and reproducible.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from code_attacks import recover_sparse_error_prange
from code_pke_reference import BitRNG, CodePKESecretKey, decrypt_bit as code_decrypt_bit
from lnat_code_bridge import LNATCodeBridgePublicKey
from lnat_code_kem import (
    LNATCodeKEMCiphertext,
    _bits_to_bytes,
    _ciphertext_body,
    _confirmation_tag,
    _public_context,
    _session_key,
)


@dataclass(frozen=True)
class PublicCodeKEMRecoveryResult:
    session_key: bytes
    encapsulated_seed: bytes
    recovered_witness: int
    prange_subsets_sampled: int
    prange_invertible_subsets: int


def recover_code_kem_from_public_data(
    pk: LNATCodeBridgePublicKey,
    ct: LNATCodeKEMCiphertext,
    *,
    rng: BitRNG | None = None,
    max_subsets: int = 100_000,
) -> PublicCodeKEMRecoveryResult:
    """Recover the exact research-KEM session key from public data when ISD wins."""
    params = ct.params
    if pk.params != params.bridge:
        raise ValueError("public key and ciphertext parameters do not match")

    recovery = recover_sparse_error_prange(
        pk.code_key,
        rng=rng,
        max_subsets=max_subsets,
    )
    code_secret = CodePKESecretKey(recovery.witness, params.bridge.code)
    bits = tuple(code_decrypt_bit(code_secret, bit_ct) for bit_ct in ct.bit_ciphertexts)
    seed_material = _bits_to_bytes(bits)

    body = _ciphertext_body(ct)
    public_digest = hashlib.sha256(_public_context(pk, params)).digest()
    expected_tag = _confirmation_tag(
        seed_material,
        public_digest,
        body,
        params.confirmation_tag_bytes,
    )
    if not hmac.compare_digest(expected_tag, ct.confirmation_tag):
        raise ValueError("recovered witness did not validate the ciphertext confirmation tag")

    key = _session_key(
        seed_material,
        public_digest,
        body,
        ct.confirmation_tag,
    )
    return PublicCodeKEMRecoveryResult(
        session_key=key,
        encapsulated_seed=seed_material,
        recovered_witness=recovery.witness,
        prange_subsets_sampled=recovery.subsets_sampled,
        prange_invertible_subsets=recovery.invertible_subsets,
    )
