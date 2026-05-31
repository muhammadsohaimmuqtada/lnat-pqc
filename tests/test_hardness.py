import os
import secrets

from lnat_pqc.lnat_core import LNATAutomaton, generate_input_sequence, generate_seed
from lnat_pqc.lnat_params import LNAT128


def test_hardness_demo_sanity():
    params = LNAT128

    seed = generate_seed(params)
    nonce = os.urandom(16)
    automaton = LNATAutomaton(seed, params)
    q0 = automaton.derive_q0(nonce)

    _, input_sequence = generate_input_sequence(params)
    y_noisy = automaton.run_noisy(q0, input_sequence, rng=secrets.SystemRandom())
    y_clean = automaton.run_noiseless(q0, input_sequence)

    attacker_q0 = 0
    attacker_table = {}
    contradictions = 0
    for t, inp in enumerate(input_sequence):
        obs_out = y_noisy[t]
        guessed_state = (attacker_q0 + t * 7) % (2 ** min(params.n, 16))
        key = (guessed_state, inp)
        if key in attacker_table and attacker_table[key] != obs_out:
            contradictions += 1
        attacker_table[key] = obs_out

    total_entries = 2 ** min(params.n + params.m, 24)
    fill_percentage = 100.0 * len(attacker_table) / total_entries

    y_recovered = automaton.run_noiseless(q0, input_sequence)
    matches = sum(a == b for a, b in zip(y_recovered, y_clean))

    assert matches == params.T
    assert fill_percentage < 0.01
    assert contradictions >= 0
