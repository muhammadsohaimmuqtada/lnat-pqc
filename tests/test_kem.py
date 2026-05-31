import os
import secrets

from lnat_pqc.lnat_core import LNATAutomaton, generate_input_sequence
from lnat_pqc.lnat_kem import LNATKEM
from lnat_pqc.lnat_params import LNAT128


def test_basic_round_trip_correctness():
    kem = LNATKEM(LNAT128)
    pk, sk = kem.keygen()
    ct, k_enc = kem.encap(pk)
    k_dec = kem.decap(sk, pk, ct)

    assert k_enc == k_dec
    assert len(k_enc) == 32
    assert len(ct.ct_bits) > 0
    assert len(pk.Y) == LNAT128.T


def test_independent_keypairs_are_independent():
    kem = LNATKEM(LNAT128)
    pk1, sk1 = kem.keygen()
    pk2, sk2 = kem.keygen()
    ct1, k1 = kem.encap(pk1)
    ct2, k2 = kem.encap(pk2)
    k1_dec = kem.decap(sk1, pk1, ct1)
    k2_dec = kem.decap(sk2, pk2, ct2)

    assert k1 == k1_dec
    assert k2 == k2_dec
    assert k1 != k2
    assert sk1.seed != sk2.seed
    assert pk1.Y != pk2.Y


def test_wrong_private_key_fails():
    kem = LNATKEM(LNAT128)
    pk1, _ = kem.keygen()
    _, sk2 = kem.keygen()
    ct, k_correct = kem.encap(pk1)
    k_wrong = kem.decap(sk2, pk1, ct)

    assert k_correct != k_wrong


def test_multiple_encapsulations_to_same_public_key_are_unique():
    kem = LNATKEM(LNAT128)
    pk, _ = kem.keygen()

    sessions = {kem.encap(pk)[1] for _ in range(10)}
    assert len(sessions) == 10


def test_key_sizes():
    kem = LNATKEM(LNAT128)
    pk, sk = kem.keygen()

    assert sk.size_bytes() == LNAT128.seed_size
    assert pk.size_bytes() > sk.size_bytes()


def test_determinism_same_seed_nonce_same_noiseless_output():
    seed = os.urandom(32)
    nonce = os.urandom(16)
    seed_a = os.urandom(32)

    aut1 = LNATAutomaton(seed, LNAT128)
    aut2 = LNATAutomaton(seed, LNAT128)
    q0_a = aut1.derive_q0(nonce)
    q0_b = aut2.derive_q0(nonce)
    _, input_sequence = generate_input_sequence(LNAT128, seed_A=seed_a)
    y1 = aut1.run_noiseless(q0_a, input_sequence)
    y2 = aut2.run_noiseless(q0_b, input_sequence)

    assert y1 == y2


def test_noise_rate_approximately_eta():
    seed = os.urandom(32)
    nonce = os.urandom(16)
    automaton = LNATAutomaton(seed, LNAT128)
    q0 = automaton.derive_q0(nonce)
    _, input_sequence = generate_input_sequence(LNAT128)

    y_clean = automaton.run_noiseless(q0, input_sequence)
    y_noisy = automaton.run_noisy(q0, input_sequence, rng=secrets.SystemRandom())

    flips = sum(a != b for a, b in zip(y_clean, y_noisy))
    actual_eta = flips / len(y_clean)

    assert abs(actual_eta - LNAT128.eta) < 0.05
