"""Public attacks against LNAT-CODE-KEM-1 research profiles.

KEM-1 improves transport efficiency but deliberately keeps the same security
boundary: the public random-code decoding instance.  Recovering that sparse
witness lets an attacker decode every outer block, validate confirmation, and
derive the exact session key without recovering the LNAT master seed.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from code_attacks import recover_sparse_error_prange
from code_pke_reference import BitRNG, CodePKESecretKey
from code_segmented_outer import decrypt_segmented_message
from lnat_code_kem1 import (
    LNATCodeKEM1Ciphertext,
    LNATCodeKEM1PublicKey,
    _ciphertext_body,
    _confirmation_tag,
    _public_context,
    _session_key,
)


@dataclass(frozen=True)
class PublicKEM1RecoveryResult:
    session_key: bytes
    encapsulated_seed: bytes
    recovered_witness: int
    prange_subsets_sampled: int
    prange_invertible_subsets: int


def recover_kem1_from_public_data(
    pk: LNATCodeKEM1PublicKey,
    ct: LNATCodeKEM1Ciphertext,
    *,
    rng: BitRNG | None = None,
    max_subsets: int = 100_000,
) -> PublicKEM1RecoveryResult:
    if pk.params != ct.params:
        raise ValueError("public key and ciphertext parameters do not match")

    recovery = recover_sparse_error_prange(
        pk.bridge_key.code_key,
        rng=rng,
        max_subsets=max_subsets,
    )
    code_secret = CodePKESecretKey(recovery.witness, pk.params.bridge.code)
    seed_material = decrypt_segmented_message(
        code_secret,
        ct.payload,
        pk.outer_code,
    )

    body = _ciphertext_body(ct)
    public_digest = hashlib.sha256(_public_context(pk)).digest()
    expected_tag = _confirmation_tag(
        seed_material,
        public_digest,
        body,
        pk.params.confirmation_tag_bytes,
    )
    if not hmac.compare_digest(expected_tag, ct.confirmation_tag):
        raise ValueError("recovered witness did not validate KEM-1 confirmation")

    key = _session_key(
        seed_material,
        public_digest,
        body,
        ct.confirmation_tag,
    )
    return PublicKEM1RecoveryResult(
        session_key=key,
        encapsulated_seed=seed_material,
        recovered_witness=recovery.witness,
        prange_subsets_sampled=recovery.subsets_sampled,
        prange_invertible_subsets=recovery.invertible_subsets,
    )
