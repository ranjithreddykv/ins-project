"""secure_dh.py - Secure-mode demonstration using the `cryptography` library.

Construction: X25519 (elliptic-curve Diffie-Hellman, RFC 7748, used in TLS 1.3)
              -> HKDF-SHA256 key derivation -> AES-256-GCM authenticated encryption.
Authentication demo: Ed25519 signatures over the handshake transcript.

No primitive is implemented from scratch. Kept fully separate from dh_core.py.
NOTE: a strong key exchange alone does NOT stop a MITM; authentication is required.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HKDF_INFO = b"dh-simulator session key v1"
TRANSCRIPT_LABEL = b"dh-simulator handshake v1"


def raw_public_bytes(pub: x25519.X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_session_key(shared_secret: bytes, transcript: bytes) -> bytes:
    """HKDF-SHA256 -> 32-byte key. The transcript is the salt (binds the key to the handshake)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript, info=HKDF_INFO).derive(shared_secret)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM; returns nonce || ciphertext+tag. A fresh random 96-bit nonce is used per message."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Raises InvalidTag if the key is wrong or the data was modified."""
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


def key_fingerprint(key: bytes) -> str:
    """Display a fingerprint rather than the key itself."""
    return hashlib.sha256(key).hexdigest()[:16]


@dataclass(frozen=True)
class SecureExchangeResult:
    alice_public_hex: str
    bob_public_hex: str
    keys_match: bool
    key_fingerprint: str
    ciphertext_hex: str
    decrypted: str
    tamper_detected: bool


def run_secure_exchange(message: str = "Hello Bob, this is Alice.") -> SecureExchangeResult:
    """Ephemeral X25519 exchange + HKDF + AES-GCM. Private keys are never returned."""
    alice, bob = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    A, B = raw_public_bytes(alice.public_key()), raw_public_bytes(bob.public_key())
    transcript = TRANSCRIPT_LABEL + A + B
    k_alice = derive_session_key(alice.exchange(bob.public_key()), transcript)
    k_bob = derive_session_key(bob.exchange(alice.public_key()), transcript)
    blob = aead_encrypt(k_alice, message.encode("utf-8"), aad=transcript)
    plain = aead_decrypt(k_bob, blob, aad=transcript).decode("utf-8")
    flipped = blob[:-1] + bytes([blob[-1] ^ 1])          # attacker flips one bit
    try:
        aead_decrypt(k_bob, flipped, aad=transcript)
        detected = False
    except InvalidTag:
        detected = True
    return SecureExchangeResult(A.hex(), B.hex(), k_alice == k_bob, key_fingerprint(k_alice),
                                blob.hex(), plain, detected)


# ------------------------- authentication (conceptual) ---------------------- #
def verify_signature(identity_pub: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        identity_pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


@dataclass(frozen=True)
class SignedHandshakeResult:
    honest_signature_valid: bool    # Alice verifies Bob's genuine signature
    mitm_signature_valid: bool      # Alice verifies Mallory's forged value
    explanation: str


def signed_handshake_demo() -> SignedHandshakeResult:
    """Bob signs the transcript (A || B) with his long-term Ed25519 identity key.

    Alice already trusts Bob's identity public key (in TLS: via a certificate chain).
    Mallory substitutes her own ephemeral key M; she cannot sign (A || M) as Bob.
    """
    bob_identity = ed25519.Ed25519PrivateKey.generate()
    bob_identity_pub = bob_identity.public_key()          # known/trusted by Alice
    mallory_identity = ed25519.Ed25519PrivateKey.generate()

    A = raw_public_bytes(x25519.X25519PrivateKey.generate().public_key())
    B = raw_public_bytes(x25519.X25519PrivateKey.generate().public_key())
    M = raw_public_bytes(x25519.X25519PrivateKey.generate().public_key())

    honest_sig = bob_identity.sign(TRANSCRIPT_LABEL + A + B)
    forged_sig = mallory_identity.sign(TRANSCRIPT_LABEL + A + M)   # best Mallory can do
    ok = verify_signature(bob_identity_pub, honest_sig, TRANSCRIPT_LABEL + A + B)
    bad = verify_signature(bob_identity_pub, forged_sig, TRANSCRIPT_LABEL + A + M)
    return SignedHandshakeResult(
        ok, bad,
        "Alice accepts B only if Bob's signature over the handshake verifies under Bob's trusted "
        "identity key. Mallory's substituted key fails verification, so the MITM is detected.")
