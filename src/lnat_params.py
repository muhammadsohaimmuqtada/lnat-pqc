"""Experimental parameter profiles for LNAT research.

The names in this module describe state-size profiles only. They are not
claims of classical, quantum, or NIST security strength.
"""

from dataclasses import dataclass

SCHEME_VERSION = "LNAT-EXP1"
IMPLEMENTED_REPETITION_FACTOR = 7


@dataclass(frozen=True)
class LNATParams:
    """Parameters for an LNAT experiment profile.

    `n`, `m`, and `T` are engineering/research parameters. `kappa` is the
    message width used by the archived KEM-v1 experiment. None of these
    values should be interpreted as a proven security level.
    """

    name: str
    n: int
    m: int
    T: int
    eta: float
    kappa: int | None = None
    seed_size: int = 32

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("parameter name must be non-empty")
        if self.n <= 0:
            raise ValueError("n must be positive")
        if self.m <= 0:
            raise ValueError("m must be positive")
        if self.T <= 0:
            raise ValueError("T must be positive")
        if not 0.0 <= self.eta <= 1.0:
            raise ValueError("eta must be in [0, 1]")
        if self.seed_size <= 0:
            raise ValueError("seed_size must be positive")
        if self.kappa is None:
            object.__setattr__(self, "kappa", self.n // 2)
        if self.kappa <= 0:
            raise ValueError("kappa must be positive")

    @property
    def domain_id(self) -> bytes:
        """Stable identifier used for domain separation."""
        return f"{SCHEME_VERSION}|{self.name}".encode("ascii")

    def public_trace_size_bytes(self) -> int:
        """Size of the current public trace serialization used by KEM-v1."""
        return 32 + 16 + 4 + (self.T + 7) // 8

    def private_seed_size_bytes(self) -> int:
        return self.seed_size

    def broken_kem_v1_ciphertext_size_bytes(self) -> int:
        """Ciphertext size of the archived, insecure KEM-v1 experiment."""
        return (IMPLEMENTED_REPETITION_FACTOR * self.kappa + 7) // 8


LNAT128 = LNATParams(
    name="LNAT-n128-exp1",
    n=128,
    m=8,
    T=512,
    eta=0.05,
)

LNAT192 = LNATParams(
    name="LNAT-n192-exp1",
    n=192,
    m=8,
    T=768,
    eta=0.05,
)

LNAT256 = LNATParams(
    name="LNAT-n256-exp1",
    n=256,
    m=16,
    T=1024,
    eta=0.05,
)

DEFAULT_PARAMS = LNAT128
ALL_PARAMS = {
    LNAT128.name: LNAT128,
    LNAT192.name: LNAT192,
    LNAT256.name: LNAT256,
}
