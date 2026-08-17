"""Reproduce the complete public-data break of archived LNAT KEM-v1."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_kem import LNATKEM, recover_session_key_from_public_data
from lnat_params import LNATParams


PARAMS = LNATParams(
    name="LNAT-kem-v1-break-demo",
    n=32,
    m=4,
    T=128,
    eta=0.0,
    kappa=16,
)


def main() -> int:
    kem = LNATKEM(PARAMS, allow_broken=True)
    public_key, _private_key = kem.keygen()
    ciphertext, legitimate_key = kem.encap(public_key)
    attacker_key = recover_session_key_from_public_data(public_key, ciphertext)

    print("LNAT KEM-v1 public-data recovery")
    print(f"legitimate={legitimate_key.hex()}")
    print(f"attacker  ={attacker_key.hex()}")
    print(f"recovered ={attacker_key == legitimate_key}")
    return 0 if attacker_key == legitimate_key else 1


if __name__ == "__main__":
    raise SystemExit(main())
