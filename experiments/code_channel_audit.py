#!/usr/bin/env python3
"""Report channel capacity and repetition overhead for code-PKE research profiles."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from code_channel_audit import audit_repetition_efficiency
from code_pke_reference import CodePKEParams


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=256)
    parser.add_argument("--k", type=int, default=128)
    parser.add_argument("--secret-weight", type=int, default=30)
    parser.add_argument("--error-weight", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=233)
    parser.add_argument("--cutoff", type=int, default=66)
    parser.add_argument("--message-bits", type=int, default=128)
    parser.add_argument("--tag-bytes", type=int, default=16)
    args = parser.parse_args()

    if args.repetitions <= 0:
        parser.error("--repetitions must be positive")
    if not 0 < args.cutoff <= args.repetitions:
        parser.error("--cutoff must be in [1,repetitions]")

    params = CodePKEParams(
        n=args.n,
        k=args.k,
        secret_weight=args.secret_weight,
        encryption_error_weight=args.error_weight,
        repetitions=args.repetitions,
        zero_threshold=args.cutoff / args.repetitions,
    )
    audit = audit_repetition_efficiency(
        params,
        message_bits=args.message_bits,
        confirmation_tag_bytes=args.tag_bytes,
    )

    print(f"n={params.n}")
    print(f"k={params.k}")
    print(f"secret-weight={params.secret_weight}")
    print(f"error-weight={params.encryption_error_weight}")
    print(f"message-bits={audit.message_bits}")
    print(f"zero-channel-one-probability={audit.channel.zero_one_probability:.12f}")
    print(f"channel-capacity-bits-per-use={audit.channel.capacity_bits_per_use:.12f}")
    print(f"capacity-optimal-input-one-probability={audit.channel.optimal_input_one_probability:.12f}")
    print(f"word-bytes={audit.word_bytes}")
    print(f"repetition-channel-uses={audit.repetition_channel_uses}")
    print(f"capacity-lower-bound-channel-uses={audit.capacity_lower_bound_channel_uses}")
    print(f"repetition-ciphertext-bytes={audit.repetition_ciphertext_bytes}")
    print(f"capacity-lower-bound-ciphertext-bytes={audit.capacity_lower_bound_ciphertext_bytes}")
    print(f"channel-use-overhead-ratio={audit.channel_use_overhead_ratio:.6f}")
    print(f"ciphertext-overhead-ratio={audit.ciphertext_overhead_ratio:.6f}")
    print("interpretation=capacity is a theoretical lower bound; finite reliable coding requires overhead")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
