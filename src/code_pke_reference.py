"""Toy Alekhnovich-style code-based public-key encryption reference.

This module is a research comparator, not a production cryptosystem and not a
security claim for LNAT.  It implements the public-key asymmetry pattern used
by Alekhnovich's random-code encryption construction:

* public key: a random binary linear code C and one noisy codeword c + e;
* secret key: the sparse error e;
* Enc(0): a random word from span(C, c + e)^perp plus a fresh sparse error;
* Enc(1): a uniform word;
* Dec: inner-product ciphertext words with e and distinguish biased-vs-uniform.

The implementation deliberately uses tiny/simple parameters and repetition so
that the mechanism, correctness failures, and attacks can be studied directly.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable, Protocol


class BitRNG(Protocol):
    def getrandbits(self, k: int) -> int: ...
    def sample(self, population, k: int): ...


def parity(value: int) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError("value must be a non-negative integer")
    return value.bit_count() & 1


def inner_product(left: int, right: int) -> int:
    return parity(left & right)


def gf2_rref(rows: Iterable[int], n: int) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Return reduced row-echelon form and pivot columns over GF(2)."""
    if n <= 0:
        raise ValueError("n must be positive")
    mask = (1 << n) - 1
    work = []
    for row in rows:
        if not isinstance(row, int) or row < 0 or row > mask:
            raise ValueError("row is outside the vector space")
        if row:
            work.append(row)

    pivot_row = 0
    pivots: list[int] = []
    for column in range(n):
        selected = next(
            (index for index in range(pivot_row, len(work)) if (work[index] >> column) & 1),
            None,
        )
        if selected is None:
            continue
        work[pivot_row], work[selected] = work[selected], work[pivot_row]
        pivot = work[pivot_row]
        for index in range(len(work)):
            if index != pivot_row and ((work[index] >> column) & 1):
                work[index] ^= pivot
        pivots.append(column)
        pivot_row += 1
        if pivot_row == len(work):
            break

    return tuple(work[:pivot_row]), tuple(pivots)


def gf2_rank(rows: Iterable[int], n: int) -> int:
    return len(gf2_rref(rows, n)[1])


def nullspace_basis(rows: Iterable[int], n: int) -> tuple[int, ...]:
    """Basis of vectors orthogonal to every supplied row."""
    rref, pivots = gf2_rref(rows, n)
    pivot_set = set(pivots)
    basis: list[int] = []
    for free in range(n):
        if free in pivot_set:
            continue
        vector = 1 << free
        for row, pivot in zip(rref, pivots):
            if (row >> free) & 1:
                vector |= 1 << pivot
        basis.append(vector)
    return tuple(basis)


def _rng(rng: BitRNG | None) -> BitRNG:
    return secrets.SystemRandom() if rng is None else rng


def sparse_vector(n: int, weight: int, *, rng: BitRNG | None = None) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if not 0 <= weight <= n:
        raise ValueError("weight must be in [0, n]")
    source = _rng(rng)
    vector = 0
    for position in source.sample(range(n), weight):
        vector |= 1 << position
    return vector


def random_linear_combination(rows: Iterable[int], *, rng: BitRNG | None = None) -> int:
    source = _rng(rng)
    value = 0
    for row in rows:
        if source.getrandbits(1):
            value ^= row
    return value


def random_full_rank_code(n: int, k: int, *, rng: BitRNG | None = None) -> tuple[int, ...]:
    if not 0 < k < n:
        raise ValueError("require 0 < k < n")
    source = _rng(rng)
    rows: list[int] = []
    rank = 0
    while rank < k:
        candidate = source.getrandbits(n)
        if candidate == 0:
            continue
        new_rank = gf2_rank((*rows, candidate), n)
        if new_rank > rank:
            rows.append(candidate)
            rank = new_rank
    return tuple(rows)


@dataclass(frozen=True)
class CodePKEParams:
    n: int = 128
    k: int = 64
    secret_weight: int = 4
    encryption_error_weight: int = 4
    repetitions: int = 64
    zero_threshold: float = 0.25

    def __post_init__(self) -> None:
        if not 0 < self.k < self.n:
            raise ValueError("require 0 < k < n")
        if not 0 < self.secret_weight < self.n:
            raise ValueError("secret_weight must be in (0, n)")
        if not 0 <= self.encryption_error_weight < self.n:
            raise ValueError("invalid encryption_error_weight")
        if self.repetitions <= 0:
            raise ValueError("repetitions must be positive")
        if not 0.0 < self.zero_threshold < 0.5:
            raise ValueError("zero_threshold must be in (0, 0.5)")


@dataclass(frozen=True)
class CodePKEPublicKey:
    generator: tuple[int, ...]
    noisy_codeword: int
    params: CodePKEParams

    def __post_init__(self) -> None:
        if len(self.generator) != self.params.k:
            raise ValueError("generator row count does not match k")
        if gf2_rank(self.generator, self.params.n) != self.params.k:
            raise ValueError("generator must have full row rank")
        if not 0 <= self.noisy_codeword < (1 << self.params.n):
            raise ValueError("noisy_codeword is outside the vector space")
        if gf2_rank((*self.generator, self.noisy_codeword), self.params.n) != self.params.k + 1:
            raise ValueError("noisy_codeword must extend the public code")


@dataclass(frozen=True)
class CodePKESecretKey:
    error: int
    params: CodePKEParams

    def __post_init__(self) -> None:
        if self.error.bit_count() != self.params.secret_weight:
            raise ValueError("secret error has the wrong Hamming weight")


@dataclass(frozen=True)
class CodePKECiphertext:
    words: tuple[int, ...]
    params: CodePKEParams

    def __post_init__(self) -> None:
        if len(self.words) != self.params.repetitions:
            raise ValueError("ciphertext repetition count mismatch")
        mask = (1 << self.params.n) - 1
        if any(not isinstance(word, int) or word < 0 or word > mask for word in self.words):
            raise ValueError("ciphertext word outside vector space")


def keygen(
    params: CodePKEParams = CodePKEParams(),
    *,
    rng: BitRNG | None = None,
) -> tuple[CodePKEPublicKey, CodePKESecretKey]:
    source = _rng(rng)
    generator = random_full_rank_code(params.n, params.k, rng=source)
    codeword = random_linear_combination(generator, rng=source)

    while True:
        error = sparse_vector(params.n, params.secret_weight, rng=source)
        noisy = codeword ^ error
        if gf2_rank((*generator, noisy), params.n) == params.k + 1:
            break

    return (
        CodePKEPublicKey(generator, noisy, params),
        CodePKESecretKey(error, params),
    )


def public_dual_basis(pk: CodePKEPublicKey) -> tuple[int, ...]:
    return nullspace_basis((*pk.generator, pk.noisy_codeword), pk.params.n)


def encrypt_bit(
    pk: CodePKEPublicKey,
    bit: int,
    *,
    rng: BitRNG | None = None,
) -> CodePKECiphertext:
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    source = _rng(rng)
    params = pk.params
    words: list[int] = []

    if bit == 1:
        words = [source.getrandbits(params.n) for _ in range(params.repetitions)]
    else:
        dual = public_dual_basis(pk)
        for _ in range(params.repetitions):
            codeword = random_linear_combination(dual, rng=source)
            error = sparse_vector(params.n, params.encryption_error_weight, rng=source)
            words.append(codeword ^ error)

    return CodePKECiphertext(tuple(words), params)


def decryption_statistic(sk: CodePKESecretKey, ct: CodePKECiphertext) -> float:
    if sk.params != ct.params:
        raise ValueError("parameter mismatch")
    ones = sum(inner_product(word, sk.error) for word in ct.words)
    return ones / len(ct.words)


def decrypt_bit(sk: CodePKESecretKey, ct: CodePKECiphertext) -> int:
    statistic = decryption_statistic(sk, ct)
    return 0 if statistic < sk.params.zero_threshold else 1


def public_secret_orthogonality_holds(
    pk: CodePKEPublicKey,
    sk: CodePKESecretKey,
) -> bool:
    """Check the algebraic relation that makes Enc(0) decryptable."""
    if pk.params != sk.params:
        raise ValueError("parameter mismatch")
    return all(inner_product(row, sk.error) == 0 for row in public_dual_basis(pk))


if __name__ == "__main__":
    params = CodePKEParams()
    pk, sk = keygen(params)
    for bit in (0, 1):
        ct = encrypt_bit(pk, bit)
        recovered = decrypt_bit(sk, ct)
        print(
            f"bit={bit} recovered={recovered} "
            f"statistic={decryption_statistic(sk, ct):.3f}"
        )
    print("status=toy Alekhnovich-style reference; not production cryptography")
