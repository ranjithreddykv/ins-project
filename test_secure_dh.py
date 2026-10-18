import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
pytest.importorskip("cryptography")
import secure_dh as sd


def test_secure_exchange():
    r = sd.run_secure_exchange("hi")
    assert r.keys_match and r.decrypted == "hi" and r.tamper_detected


def test_signed_handshake_detects_mitm():
    r = sd.signed_handshake_demo()
    assert r.honest_signature_valid and not r.mitm_signature_valid
