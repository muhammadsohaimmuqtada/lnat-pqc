#!/usr/bin/env python3
"""Empirical multi-bit packing probe over the LNAT code bridge channel."""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_channel_audit import audit_repetition_efficiency
from code_outer_channel import (
    decrypt_bridge_outer_message,
    encrypt_bridge_outer_message,
    generate_outer_linear_code,
)
from code_pke_reference import CodePKEParams
from lnat_code_bridge import LNATCodeBridgeParams, keygen
from lnat_params import LNATParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=32)
    parser.add_argument("--channel-uses", type=int, default=128)
    args = parser.parse_args()
    if args.trials <= 0:
        parser.error("--trials must be positive")

    bridge = LNATCodeBridgeParams(
        code=CodePKEParams(
            n=64,
            k=32,
            secret_weight=2,
            encryption_error_weight=1,
            repetitions=96,
            zero_threshold=0.25,
        ),
        lnat=LNATParams(
            name="LNAT-outer-channel-probe",
            n=32,
            m=4,
            T=32,
            eta=0.0,
            seed_size=32,
        ),
    )
    pk, sk = keygen(bridge, rng=random.Random(51001))
    outer = generate_outer_linear_code(8, args.channel_uses, rng=random.Random(51002))
    message_rng = random.Random(51003)

    failures = 0
    for trial in range(args.trials):
        message = message_rng.randrange(256)
        ct = encrypt_bridge_outer_message(
            pk,
            outer,
            message,
            rng=random.Random(52000 + trial),
        )
        recovered = decrypt_bridge_outer_message(sk, pk, ct, outer)
        failures += recovered != message

    repetition = audit_repetition_efficiency(
        bridge.code,
        message_bits=8,
        confirmation_tag_bytes=0,
    )
    word_bytes = (bridge.code.n + 7) // 8
    outer_bytes = outer.channel_uses * word_bytes
    repetition_bytes = 8 * bridge.code.repetitions * word_bytes

    print(f"trials={args.trials}")
    print(f"message-bits=8")
    print(f"outer-channel-uses={outer.channel_uses}")
    print(f"outer-rate={outer.rate:.6f}")
    print(f"outer-ciphertext-bytes={outer_bytes}")
    print(f"repetition-channel-uses={8 * bridge.code.repetitions}")
    print(f"repetition-ciphertext-bytes={repetition_bytes}")
    print(f"word-count-reduction={repetition.repetition_channel_uses / outer.channel_uses:.6f}x")
    print(f"capacity-bits-per-use={repetition.channel.capacity_bits_per_use:.6f}")
    print(f"empirical-failures={failures}")
    print("decoder=exhaustive maximum likelihood; reduced parameters only")
    print("interpretation=packing proof-of-concept, not a scalable KEM code")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
