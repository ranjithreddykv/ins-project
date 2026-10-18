import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
import dh_core as dh
import mitm_simulation as mitm

FIXED = dict(p=23, g=5, a=6, b=15, mallory_a=3, mallory_b=9)


def test_fixed_keys_give_distinct_secrets():
    r = mitm.simulate_mitm(**FIXED)
    assert r.alice_secret != r.bob_secret
    assert r.secrets_differ and r.detectable_by_fingerprint


def test_mallory_shares_a_secret_with_each_victim():
    r = mitm.simulate_mitm(**FIXED)
    assert r.mallory_secret_with_alice == r.alice_secret
    assert r.mallory_secret_with_bob == r.bob_secret
    assert r.mallory_knows_both


def test_mallory_reads_and_relays_message():
    r = mitm.simulate_mitm(**FIXED, message="hello bob")
    assert r.mallory_read == "hello bob"
    assert r.bob_received == "hello bob" and not r.tampered


def test_mallory_can_tamper():
    r = mitm.simulate_mitm(**FIXED, message="pay 5", tampered_message="pay 5000")
    assert r.tampered and r.bob_received == "pay 5000"


def test_original_ciphertext_unreadable_to_bob():
    r = mitm.simulate_mitm(**FIXED, message="a fairly long secret message")
    assert r.bob_decrypt_of_original != r.message


def test_auto_keys_produce_distinct_secrets_in_larger_group():
    for _ in range(30):
        r = mitm.simulate_mitm(1019, 2)
        assert r.mallory_knows_both and r.secrets_differ


def test_invalid_inputs():
    with pytest.raises(dh.InvalidParameterError):
        mitm.simulate_mitm(22, 5)
    with pytest.raises(dh.InvalidKeyError):
        mitm.simulate_mitm(23, 5, a=1)
    with pytest.raises(dh.InvalidKeyError):
        mitm.simulate_mitm(23, 5, mallory_b=22)
    with pytest.raises(ValueError):
        mitm.simulate_mitm(23, 5, message="")


def test_toy_cipher_roundtrip_and_wrong_key():
    ct = mitm.toy_encrypt(7, 1019, "round trip")
    assert mitm.toy_decrypt(7, 1019, ct) == "round trip"
    assert mitm.toy_decrypt(8, 1019, ct) != "round trip"
