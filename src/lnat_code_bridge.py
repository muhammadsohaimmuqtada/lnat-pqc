"""LNAT-CODE-BRIDGE-0: research bridge from LNAT state dynamics to code PKE.

This is NOT a standalone LNAT KEM and makes no new security claim.

The public-key asymmetry is still the Alekhnovich-style random-code relation
implemented in ``code_pke_reference``.  LNAT-EXP2 is used only to derive the
hidden sparse decoding witness from a compact secret seed and public schedule.
The point of this module is to test a safe integration boundary without
pretending the secret-seeded LNAT automaton is publicly evaluable.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Protocol

from code_pke_reference import (
    BitRNG,
    CodePKECiphertext,
    CodePKEParams,
    CodePKEPublicKey,
    CodePKESecretKey,
    decrypt_bit as code_decrypt_bit,
    encrypt_bit as code_encrypt_bit,
    gf2_rank,
    public_secret_orthogonality_holds,
    random_full_rank_code,
    random_linear_combination,
)
from lnat_core import LNATAutomaton, generate_input_sequence, prf
from lnat_params import LNAT128, LNATParams

BRIDGE_VERSION = "LNAT-CODE-BRIDGE-0"


class ByteBitRNG(BitRNG, Protocol):
    pass


def _rng(rng: ByteBitRNG | None) -> ByteBitRNG:
    return secrets.SystemRandom() if rng is None else rng


def _random_bytes(source: ByteBitRNG, length: int) -> bytes:
    return bytes(source.getrandbits(8) for _ in range(length))


@dataclass(frozen=True)
class LNATCodeBridgeParams:
    code: CodePKEParams = CodePKEParams()
    lnat: LNATParams = LNAT128

    def __post_init__(self) -> None:
        if self.lnat.T <= 0:
            raise ValueError("LNAT profile must contain at least one transition")
        if self.code.secret_weight > self.code.n:
            raise ValueError("code witness weight exceeds code length")

    @property
    def witness_space_bits(self) -> float:
        """Log2 of the sparse-witness support size C(n,w).

        This is an upper bound on effective witness entropy regardless of how
        large the LNAT seed is.  A 256-bit seed does not turn a tiny sparse
        witness space into 256 bits of security.
        """
        return math.log2(math.comb(self.code.n, self.code.secret_weight))


@dataclass(frozen=True)
class LNATCodeBridgePublicKey:
    code_key: CodePKEPublicKey
    nonce: bytes
    input_seed: bytes
    params: LNATCodeBridgeParams

    def __post_init__(self) -> None:
        if self.code_key.params != self.params.code:
            raise ValueError("code parameter mismatch")
        if len(self.nonce) != 16:
            raise ValueError("nonce must be 16 bytes")
        if len(self.input_seed) != 32:
            raise ValueError("input_seed must be 32 bytes")


@dataclass(frozen=True)
class LNATCodeBridgeSecretKey:
    lnat_seed: bytes
    params: LNATCodeBridgeParams

    def __post_init__(self) -> None:
        if len(self.lnat_seed) != self.params.lnat.seed_size:
            raise ValueError("LNAT seed length mismatch")


def _final_lnat_state(
    seed: bytes,
    params: LNATCodeBridgeParams,
    *,
    nonce: bytes,
    input_seed: bytes,
) -> int:
    automaton = LNATAutomaton(seed, params.lnat)
    state = automaton.derive_q0(nonce)
    _, inputs = generate_input_sequence(params.lnat, input_seed)
    for inp in inputs:
        state = automaton.table.lookup(state, inp)
    return state


def derive_sparse_witness(
    seed: bytes,
    params: LNATCodeBridgeParams,
    *,
    nonce: bytes,
    input_seed: bytes,
) -> int:
    """Derive an exactly-weight-w code witness from the full LNAT state chain."""
    if len(seed) != params.lnat.seed_size:
        raise ValueError("LNAT seed length mismatch")
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    if len(input_seed) != 32:
        raise ValueError("input_seed must be 32 bytes")

    final_state = _final_lnat_state(
        seed,
        params,
        nonce=nonce,
        input_seed=input_seed,
    )
    state_bytes = (params.lnat.n + 7) // 8
    index_bits = max(1, (params.code.n - 1).bit_length())
    index_bytes = (index_bits + 7) // 8
    index_mask = (1 << index_bits) - 1
    domain = (
        params.lnat.domain_id
        + b"|CODE-BRIDGE-WITNESS|"
        + BRIDGE_VERSION.encode("ascii")
        + b"|"
        + final_state.to_bytes(state_bytes, "big")
        + nonce
        + input_seed
    )

    positions: set[int] = set()
    counter = 0
    while len(positions) < params.code.secret_weight:
        raw = prf(seed, domain + counter.to_bytes(8, "big"), index_bytes)
        candidate = int.from_bytes(raw, "big") & index_mask
        counter += 1
        if candidate < params.code.n:
            positions.add(candidate)
        if counter > 1_000_000:
            raise RuntimeError("witness derivation did not converge")

    witness = 0
    for position in positions:
        witness |= 1 << position
    return witness


def keygen(
    params: LNATCodeBridgeParams = LNATCodeBridgeParams(),
    *,
    rng: ByteBitRNG | None = None,
) -> tuple[LNATCodeBridgePublicKey, LNATCodeBridgeSecretKey]:
    source = _rng(rng)
    generator = random_full_rank_code(params.code.n, params.code.k, rng=source)
    codeword = random_linear_combination(generator, rng=source)
    lnat_seed = _random_bytes(source, params.lnat.seed_size)

    # A derived sparse witness can occasionally lie in the public code.  In
    # that case regenerate only the public schedule until the noisy word adds
    # one dimension, preserving the secret seed.
    for _ in range(1024):
        nonce = _random_bytes(source, 16)
        input_seed = _random_bytes(source, 32)
        witness = derive_sparse_witness(
            lnat_seed,
            params,
            nonce=nonce,
            input_seed=input_seed,
        )
        noisy = codeword ^ witness
        if gf2_rank((*generator, noisy), params.code.n) == params.code.k + 1:
            code_key = CodePKEPublicKey(generator, noisy, params.code)
            public = LNATCodeBridgePublicKey(code_key, nonce, input_seed, params)
            secret = LNATCodeBridgeSecretKey(lnat_seed, params)
            return public, secret

    raise RuntimeError("failed to derive a witness outside the public code")


def recover_code_secret(
    sk: LNATCodeBridgeSecretKey,
    pk: LNATCodeBridgePublicKey,
) -> CodePKESecretKey:
    if sk.params != pk.params:
        raise ValueError("bridge parameter mismatch")
    witness = derive_sparse_witness(
        sk.lnat_seed,
        sk.params,
        nonce=pk.nonce,
        input_seed=pk.input_seed,
    )
    code_secret = CodePKESecretKey(witness, sk.params.code)
    if not public_secret_orthogonality_holds(pk.code_key, code_secret):
        raise ValueError("secret seed does not match public key")
    return code_secret


def encrypt_bit(
    pk: LNATCodeBridgePublicKey,
    bit: int,
    *,
    rng: ByteBitRNG | None = None,
) -> CodePKECiphertext:
    """Public encryption; no LNAT secret is required by the sender."""
    return code_encrypt_bit(pk.code_key, bit, rng=rng)


def decrypt_bit(
    sk: LNATCodeBridgeSecretKey,
    pk: LNATCodeBridgePublicKey,
    ct: CodePKECiphertext,
) -> int:
    code_secret = recover_code_secret(sk, pk)
    return code_decrypt_bit(code_secret, ct)


if __name__ == "__main__":
    params = LNATCodeBridgeParams()
    pk, sk = keygen(params)
    print(f"bridge={BRIDGE_VERSION}")
    print(f"witness-space-bits={params.witness_space_bits:.2f}")
    for bit in (0, 1):
        ct = encrypt_bit(pk, bit)
        print(f"bit={bit} recovered={decrypt_bit(sk, pk, ct)}")
    print("security-boundary=random-code noisy-decoding comparator; not LNAT-native KEM")
