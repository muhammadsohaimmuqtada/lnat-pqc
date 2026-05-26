# lnat_params.py
# Parameter sets for LNAT-PQC
# LNAT-128, LNAT-192, LNAT-256

class LNATParams:
    """
    A parameter set for the LNAT scheme.

    Fields:
        n         : state size in bits
        m         : input chunk size in bits
        kappa     : output size in bits (n // 2)
        T         : number of automaton steps (public key length)
        eta       : noise rate (probability of output bit flip)
        bch_t     : BCH error correction capability (bits)
        seed_size : private key size in bytes
        name      : human-readable label
    """
    def __init__(self, name, n, m, T, eta, bch_t):
        self.name      = name
        self.n         = n
        self.m         = m
        self.kappa     = n // 2
        self.T         = T
        self.eta       = eta
        self.bch_t     = bch_t
        self.seed_size = 32     # always 256-bit seed

    def __repr__(self):
        return (
            f"LNATParams({self.name}: "
            f"n={self.n}, m={self.m}, T={self.T}, "
            f"eta={self.eta}, bch_t={self.bch_t})"
        )

    def security_classical(self):
        """Estimated classical security in bits."""
        return self.n

    def security_quantum(self):
        """Estimated quantum security in bits (Grover bound)."""
        return self.n // 2

    def public_key_size_bytes(self):
        """
        Estimated public key size in bytes.
        seed_A (32) + Y syndrome (~T * kappa / 8 compressed)
        """
        seed_A_bytes = 32
        Y_bytes      = (self.T * self.kappa) // 8
        return seed_A_bytes + Y_bytes

    def private_key_size_bytes(self):
        """Private key is just the seed."""
        return self.seed_size

    def ciphertext_size_bytes(self):
        """Ciphertext is approximately T * kappa bits."""
        return (self.T * self.kappa) // 8


# ──────────────────────────────────────────────────────────────────────────────
# Standard parameter sets
# ──────────────────────────────────────────────────────────────────────────────

LNAT128 = LNATParams(
    name  = "LNAT-128",
    n     = 128,       # 128-bit state
    m     = 8,         # 8-bit input chunks
    T     = 512,       # 512 automaton steps
    eta   = 0.05,      # 5% noise rate
    bch_t = 51,        # corrects up to 51/512 = ~10% errors (2x safety margin)
)

LNAT192 = LNATParams(
    name  = "LNAT-192",
    n     = 192,
    m     = 8,
    T     = 768,
    eta   = 0.05,
    bch_t = 76,
)

LNAT256 = LNATParams(
    name  = "LNAT-256",
    n     = 256,
    m     = 16,
    T     = 1024,
    eta   = 0.05,
    bch_t = 102,
)

# Default
DEFAULT_PARAMS = LNAT128

# All parameter sets in a dict for easy lookup
ALL_PARAMS = {
    "LNAT-128": LNAT128,
    "LNAT-192": LNAT192,
    "LNAT-256": LNAT256,
}


if __name__ == "__main__":
    print("LNAT Parameter Sets")
    print("=" * 60)
    for name, p in ALL_PARAMS.items():
        print(f"\n{p.name}")
        print(f"  State size (n):          {p.n} bits")
        print(f"  Input size (m):          {p.m} bits")
        print(f"  Steps (T):               {p.T}")
        print(f"  Noise rate (eta):        {p.eta}")
        print(f"  BCH correction (t):      {p.bch_t} bits")
        print(f"  Classical security:      {p.security_classical()} bits")
        print(f"  Quantum security:        {p.security_quantum()} bits")
        print(f"  Public key size:         {p.public_key_size_bytes()} bytes")
        print(f"  Private key size:        {p.private_key_size_bytes()} bytes")
        print(f"  Ciphertext size:         {p.ciphertext_size_bytes()} bytes")
    print("\nNote: Public key sizes are estimates pending BCH compression.")
    print("Formal size analysis is an open problem.")
