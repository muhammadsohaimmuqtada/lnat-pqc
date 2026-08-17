#!/usr/bin/env python3
"""Reproduce the complete public-data break of archived LNAT KEM-v1."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_kem import LNATKEM, recover_session_key_from_public_data
from lnat_params import LNATParams


def main() -> int:
    params = LNATParams("LNAT-v1-break-repro", n=32, m=4, T=128, eta=0.0, kappa=16)
    kem = LNATKEM(params, allow_broken=True)
    pk, _ = kem.keygen()
    ct, legitimate = kem.encap(pk)
    attacker = recover_session_key_from_public_data(pk, ct)
    print(f"legitimate={legitimate.hex()}")
    print(f"attacker  ={attacker.hex()}")
    print(f"recovered ={legitimate == attacker}")
    return 0 if legitimate == attacker else 1


if __name__ == "__main__":
    raise SystemExit(main())
