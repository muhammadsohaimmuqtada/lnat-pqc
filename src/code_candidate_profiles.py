"""Measured candidate profiles and engineering-footprint accounting.

Profiles in this module are *research screens*, not standardized parameter sets
and not security-level claims. They bind together the exact geometry,
decision rule, estimator measurement, and current reference KEM mechanics so
later experiments cannot silently mix incompatible numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams
from lnat_code_kem import LNATCodeKEMParams
from lnat_params import LNAT128, LNATParams


@dataclass(frozen=True)
class ResearchCodeKEMProfile:
    name: str
    n: int
    k: int
    secret_weight: int
    encryption_error_weight: int
    repetitions: int
    cutoff_ones: int
    encapsulated_seed_bytes: int
    confirmation_tag_bytes: int
    measured_effective_attack_bits: float
    estimator_algorithm: str
    estimator_version: str
    conservative_kem_failure_bound: float
    lnat: LNATParams = LNAT128

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("profile name must not be empty")
        if not 0 < self.k < self.n:
            raise ValueError("require 0 < k < n")
        if not 0 < self.secret_weight <= self.n - self.k:
            raise ValueError("secret_weight must be in [1, n-k]")
        if not 0 <= self.encryption_error_weight <= self.n:
            raise ValueError("invalid encryption_error_weight")
        if self.repetitions <= 0:
            raise ValueError("repetitions must be positive")
        if not 0 < self.cutoff_ones <= self.repetitions:
            raise ValueError("cutoff_ones must be in [1, repetitions]")
        if self.encapsulated_seed_bytes <= 0:
            raise ValueError("encapsulated_seed_bytes must be positive")
        if not 8 <= self.confirmation_tag_bytes <= 64:
            raise ValueError("confirmation_tag_bytes must be in [8, 64]")
        if self.measured_effective_attack_bits < 0:
            raise ValueError("measured_effective_attack_bits must be non-negative")
        if not 0.0 <= self.conservative_kem_failure_bound <= 1.0:
            raise ValueError("conservative_kem_failure_bound must be in [0, 1]")

    @property
    def threshold(self) -> float:
        return self.cutoff_ones / self.repetitions

    @property
    def word_bytes(self) -> int:
        return (self.n + 7) // 8

    @property
    def encapsulated_seed_bits(self) -> int:
        return 8 * self.encapsulated_seed_bytes

    @property
    def generator_bytes(self) -> int:
        return self.k * self.word_bytes

    @property
    def raw_public_code_bytes(self) -> int:
        """Generator + noisy codeword + public LNAT schedule bytes."""
        return self.generator_bytes + self.word_bytes + 16 + 32

    @property
    def public_context_bytes(self) -> int:
        """Bytes hashed by the current KEM public-context encoder.

        This is not yet a stable wire serialization. It includes the KEM version,
        domain marker, integer header, floating threshold, generator, noisy word,
        nonce, and input seed exactly as ``lnat_code_kem._public_context`` does.
        """
        kem_version_bytes = len("LNAT-CODE-KEM-0".encode("ascii"))
        public_marker_bytes = len(b"|PUBLIC|")
        header_bytes = 6 * 4
        threshold_bytes = 8
        return (
            kem_version_bytes
            + public_marker_bytes
            + header_bytes
            + threshold_bytes
            + self.raw_public_code_bytes
        )

    @property
    def ciphertext_body_bytes(self) -> int:
        return self.encapsulated_seed_bits * self.repetitions * self.word_bytes

    @property
    def ciphertext_bytes(self) -> int:
        return self.ciphertext_body_bytes + self.confirmation_tag_bytes

    @property
    def private_seed_bytes(self) -> int:
        return self.lnat.seed_size

    def to_kem_params(self) -> LNATCodeKEMParams:
        code = CodePKEParams(
            n=self.n,
            k=self.k,
            secret_weight=self.secret_weight,
            encryption_error_weight=self.encryption_error_weight,
            repetitions=self.repetitions,
            zero_threshold=self.threshold,
        )
        bridge = LNATCodeBridgeParams(code=code, lnat=self.lnat)
        return LNATCodeKEMParams(
            bridge=bridge,
            encapsulated_seed_bytes=self.encapsulated_seed_bytes,
            confirmation_tag_bytes=self.confirmation_tag_bytes,
        )


MODERN_128_SCREEN_V1 = ResearchCodeKEMProfile(
    name="LNAT-CODE-research-modern128-screen-v1",
    n=1064,
    k=532,
    secret_weight=117,
    encryption_error_weight=1,
    repetitions=220,
    cutoff_ones=61,
    encapsulated_seed_bytes=16,
    confirmation_tag_bytes=16,
    measured_effective_attack_bits=128.611921,
    estimator_algorithm="MayOzerov",
    estimator_version="2.1.1",
    conservative_kem_failure_bound=8.44167402647e-10,
)
