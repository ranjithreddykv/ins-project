import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
import dh_core as dh


def test_known_answer_textbook():
    assert dh.compute_public_key(5, 6, 23) == 8
    assert dh.compute_public_key(5, 15, 23) == 19
    assert dh.run_exchange(23, 5, 6, 15).alice_secret == 2


@pytest.mark.parametrize("name", list(dh.EDUCATIONAL_GROUPS))
def test_presets_valid_and_secrets_equal(name):
    p, g = dh.EDUCATIONAL_GROUPS[name]
    dh.validate_parameters(p, g)
    for _ in range(25):
        ex = dh.run_exchange(p, g)
        assert ex.secrets_match
        assert ex.alice_secret == pow(g, ex.a * ex.b, p)


def test_random_private_key_in_range():
    for _ in range(500):
        k = dh.generate_private_key(23)
        assert 2 <= k <= 21 and k != 11


@pytest.mark.parametrize("p,g", [(22, 5), (23, 1), (23, 22), (23, 4), (4, 2), (3, 2), (2**31 + 11, 2), (23.0, 5)])
def test_invalid_parameters(p, g):
    with pytest.raises(dh.InvalidParameterError):
        dh.validate_parameters(p, g)


@pytest.mark.parametrize("x", [0, 1, 11, 22, 23, -5, 3.5, "7", True])
def test_invalid_private_keys(x):
    with pytest.raises(dh.InvalidKeyError):
        dh.compute_public_key(5, x, 23)


@pytest.mark.parametrize("y", [0, 1, 22, 99, -1])
def test_invalid_peer_public(y):
    with pytest.raises(dh.InvalidKeyError):
        dh.compute_shared_secret(y, 6, 23)


def test_parameter_change_changes_public_keys():
    assert dh.compute_public_key(5, 6, 23) != dh.compute_public_key(5, 6, 47)
    assert dh.run_exchange(23, 5, 6, 15).A != dh.run_exchange(23, 5, 7, 15).A


def test_different_private_keys_can_give_same_secret():
    # 2*6 == 3*4 (mod 22) -> identical numerical secret from different key pairs
    s1 = dh.run_exchange(23, 5, 2, 6).alice_secret
    s2 = dh.run_exchange(23, 5, 3, 4).alice_secret
    assert s1 == s2
    assert (3, 4) in dh.find_same_secret_pairs(23, 5, 2, 6, limit=50)


def test_is_prime_and_primitive_root():
    assert [n for n in range(20) if dh.is_prime(n)] == [2, 3, 5, 7, 11, 13, 17, 19]
    assert not dh.is_prime(561)  # Carmichael number
    assert dh.is_primitive_root(5, 23) and not dh.is_primitive_root(4, 23)


def test_experiment_row():
    row = dh.experiment_row(23, 5, 6, 15)
    assert row["Match"] == "Yes" and row["A"] == 8
