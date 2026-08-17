#!/usr/bin/env python3
"""Microbenchmarks for the LNAT primitive and operational hybrid KEM."""

import argparse
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lnat_core import LNATAutomaton, generate_input_sequence, generate_seed
from lnat_hybrid_kem import LNATMLKEM768
from lnat_params import LNAT128


def measure(fn, rounds: int):
    samples = []
    for _ in range(rounds):
        start = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return statistics.median(samples), statistics.fmean(samples)


def primitive_round():
    seed = generate_seed(LNAT128)
    automaton = LNATAutomaton(seed, LNAT128)
    q0 = automaton.derive_q0(b"benchmark-nonce")
    _, inputs = generate_input_sequence(LNAT128)
    automaton.run_noiseless(q0, inputs)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--hybrid", action="store_true")
    args = parser.parse_args()
    if args.rounds <= 0:
        parser.error("--rounds must be positive")
    median, mean = measure(primitive_round, args.rounds)
    print(f"lnat-exp2-n128-median-ms={median:.3f}")
    print(f"lnat-exp2-n128-mean-ms={mean:.3f}")
    if args.hybrid:
        try:
            kem = LNATMLKEM768()
            pk, sk = kem.keygen()
        except RuntimeError as exc:
            print(f"hybrid=SKIP ({exc})")
            return 0
        def hybrid_round():
            ct, sender = kem.encap(pk)
            receiver = kem.decap(sk, pk, ct)
            if sender != receiver:
                raise RuntimeError("hybrid KEM round trip failed")
        median, mean = measure(hybrid_round, args.rounds)
        print(f"lnat-mlkem768-hybrid-median-ms={median:.3f}")
        print(f"lnat-mlkem768-hybrid-mean-ms={mean:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
