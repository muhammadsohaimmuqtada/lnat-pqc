"""Experimental parameter profiles for LNAT research.

Profile names describe engineering dimensions only. They are not claims of
classical, quantum, NIST, IND-CPA, or IND-CCA security strength.
"""

from dataclasses import dataclass

SCHEME_VERSION = "LNAT-EXP2"
IMPLEMENTED_REPETITION_FACTOR = 7


@dataclass(frozen=True)
class LNATParams:
    """Parameters for an LNAT experiment profile."""

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
            object.__setattr__(self, "kappa", max(1, self.n // 2))
        if self.kappa <= 0:
            raise ValueError("kappa must be positive")

    @property
    def domain_id(self) -> bytes:
        return f"{SCHEME_VERSION}|{self.name}".encode("ascii")

    def public_trace_size_bytes(self) -> int:
        return 32 + 16 + 4 + (self.T + 7) // 8

    def private_seed_size_bytes(self) -> int:
        return self.seed_size

    def broken_kem_v1_ciphertext_size_bytes(self) -> int:
        return (IMPLEMENTED_REPETITION_FACTOR * self.kappa + 7) // 8


LNAT128 = LNATParams("LNAT-n128-exp2", n=128, m=8, T=512, eta=0.05)
LNAT192 = LNATParams("LNAT-n192-exp2", n=192, m=8, T=768, eta=0.05)
LNAT256 = LNATParams("LNAT-n256-exp2", n=256, m=16, T=1024, eta=0.05)

DEFAULT_PARAMS = LNAT128
ALL_PARAMS = {p.name: p for p in (LNAT128, LNAT192, LNAT256)}

# Deliberately tiny profiles for attack experiments only.
TOY8 = LNATParams("LNAT-toy8-exp2", n=8, m=2, T=32, eta=0.05, kappa=4, seed_size=1)
TOY16 = LNATParams("LNAT-toy16-exp2", n=16, m=3, T=48, eta=0.05, kappa=8, seed_size=2)
