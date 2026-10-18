"""mitm_simulation.py - Simplified educational Man-in-the-Middle attack on unauthenticated DH.

NOT a real cipher: `toy_encrypt` is a hash-based XOR stream with no authentication,
used ONLY to make the consequences of a MITM visible. Real systems derive keys with
HKDF and use authenticated encryption (AES-GCM / ChaCha20-Poly1305).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import dh_core as dh


# ------------------------------ toy cipher (demo only) ---------------------- #
def secret_to_bytes(secret: int, p: int) -> bytes:
    return secret.to_bytes((p.bit_length() + 7) // 8, "big")


def _keystream(key: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def toy_encrypt(secret: int, p: int, plaintext: str) -> bytes:
    """XOR with a SHA-256-derived keystream. EDUCATIONAL ONLY."""
    data = plaintext.encode("utf-8")
    ks = _keystream(secret_to_bytes(secret, p), len(data))
    return bytes(x ^ y for x, y in zip(data, ks))


def toy_decrypt(secret: int, p: int, ciphertext: bytes) -> str:
    """Inverse of toy_encrypt; a wrong secret yields unreadable garbage."""
    ks = _keystream(secret_to_bytes(secret, p), len(ciphertext))
    return bytes(x ^ y for x, y in zip(ciphertext, ks)).decode("utf-8", errors="replace")


def fingerprint(secret: int, p: int) -> str:
    """Short hash of a secret that Alice and Bob could compare out-of-band."""
    return hashlib.sha256(secret_to_bytes(secret, p)).hexdigest()[:8]


# ------------------------------ simulation ---------------------------------- #
@dataclass(frozen=True)
class MITMResult:
    p: int
    g: int
    a: int; b: int                      # Alice / Bob private keys
    A: int; B: int                      # genuine public keys (intercepted)
    mallory_a: int; mallory_b: int      # Mallory's private keys (towards Alice / towards Bob)
    forged_to_alice: int                # g^mallory_a, posing as Bob
    forged_to_bob: int                  # g^mallory_b, posing as Alice
    alice_secret: int                   # Alice <-> Mallory
    bob_secret: int                     # Bob   <-> Mallory
    mallory_secret_with_alice: int
    mallory_secret_with_bob: int
    message: str
    ciphertext_from_alice: bytes
    mallory_read: str
    forwarded_message: str
    ciphertext_to_bob: bytes
    bob_received: str
    bob_decrypt_of_original: str        # what Bob sees if the original ciphertext were delivered

    @property
    def secrets_differ(self) -> bool:
        return self.alice_secret != self.bob_secret

    @property
    def mallory_knows_both(self) -> bool:
        return (self.mallory_secret_with_alice == self.alice_secret
                and self.mallory_secret_with_bob == self.bob_secret)

    @property
    def tampered(self) -> bool:
        return self.forwarded_message != self.message

    def fingerprints(self) -> tuple[str, str]:
        return fingerprint(self.alice_secret, self.p), fingerprint(self.bob_secret, self.p)

    @property
    def detectable_by_fingerprint(self) -> bool:
        """Comparing secret fingerprints out-of-band would reveal the attack."""
        fa, fb = self.fingerprints()
        return fa != fb


def simulate_mitm(p: int, g: int, a: Optional[int] = None, b: Optional[int] = None,
                  mallory_a: Optional[int] = None, mallory_b: Optional[int] = None,
                  message: str = "Transfer 500 to account 1234",
                  tampered_message: Optional[str] = None) -> MITMResult:
    """Simulate Alice <-> Mallory <-> Bob. Missing keys are generated with `secrets`."""
    dh.validate_parameters(p, g)
    a = dh.generate_private_key(p) if a is None else a
    b = dh.generate_private_key(p) if b is None else b
    for k in (a, b, mallory_a, mallory_b):
        if k is not None:
            dh.validate_private_key(k, p)
    if not isinstance(message, str) or not message:
        raise ValueError("Message must be a non-empty string.")

    A, B = dh.compute_public_key(g, a, p), dh.compute_public_key(g, b, p)

    # Mallory picks keys; when auto-generating, retry so the two secrets differ.
    auto = mallory_a is None and mallory_b is None
    for _ in range(200):
        ma = dh.generate_private_key(p) if mallory_a is None else mallory_a
        mb = dh.generate_private_key(p) if mallory_b is None else mallory_b
        M_to_alice, M_to_bob = dh.compute_public_key(g, ma, p), dh.compute_public_key(g, mb, p)
        s_alice = dh.compute_shared_secret(M_to_alice, a, p)   # Alice thinks M_to_alice is Bob's key
        s_bob = dh.compute_shared_secret(M_to_bob, b, p)       # Bob thinks M_to_bob is Alice's key
        if not auto or s_alice != s_bob:
            break
    m_with_alice = dh.compute_shared_secret(A, ma, p)
    m_with_bob = dh.compute_shared_secret(B, mb, p)

    # Message relay: Alice -> Mallory -> Bob
    ct_a = toy_encrypt(s_alice, p, message)
    read = toy_decrypt(m_with_alice, p, ct_a)
    forwarded = tampered_message if tampered_message else read
    ct_b = toy_encrypt(m_with_bob, p, forwarded)
    bob_got = toy_decrypt(s_bob, p, ct_b)
    bob_raw = toy_decrypt(s_bob, p, ct_a)

    return MITMResult(p, g, a, b, A, B, ma, mb, M_to_alice, M_to_bob, s_alice, s_bob,
                      m_with_alice, m_with_bob, message, ct_a, read, forwarded, ct_b,
                      bob_got, bob_raw)
