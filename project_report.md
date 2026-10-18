# Diffie–Hellman Key Exchange Simulator: Secure Shared-Secret Establishment and Man-in-the-Middle Attack Demonstration

## 1. Objective
Implement and demonstrate Diffie–Hellman (DH), show how changing keys and parameters affects results, and explain why unauthenticated DH is vulnerable to MITM attacks.

## 2. Background
Two parties agree on a prime `p` and generator `g`. Alice computes `A = gᵃ mod p`, Bob computes `B = gᵇ mod p`. Each combines the peer's public value with their own secret: `Bᵃ = gᵃᵇ = Aᵇ (mod p)`. An eavesdropper sees `p, g, A, B` but must solve the discrete logarithm problem to recover `a` or `b`. DH is a **key-agreement** protocol, not an encryption algorithm.

## 3. Design
| Module | Responsibility |
|---|---|
| `dh_core.py` | Primality (Miller–Rabin), primitive-root check, key generation with `secrets`, public keys, shared secret, validation, experiment helpers |
| `mitm_simulation.py` | Alice–Mallory–Bob simulation, toy stream cipher, fingerprints |
| `secure_dh.py` | X25519, HKDF-SHA256, AES-256-GCM, Ed25519 signature demo (`cryptography`) |
| `app.py` | Streamlit UI with seven tabs |

Design decisions: validation rejects non-prime `p`, non-generators, private keys outside `[2, p-2]`, and the weak key `(p-1)/2` (public key `p-1`). Peer public values 0, 1, p-1 are rejected.

## 4. Implementation highlights
- Educational parameters limited to `p ≤ 2³¹−1` so the generator can be verified by factoring `p−1`.
- Random keys use `secrets.randbelow`.
- Shared secrets are computed independently on both sides; the match is *verified*, never hardcoded.
- MITM: Mallory holds two private keys; Alice shares `s₁ = g^(a·m₁)` and Bob `s₂ = g^(b·m₂)` with her. She decrypts, optionally modifies, and re-encrypts messages.
- Secure mode derives a session key with HKDF using the handshake transcript as salt, protects data with AES-GCM, and demonstrates that bit-flips are detected.

## 5. Testing
43 pytest cases cover: known-answer vector (p=23, g=5, a=6, b=15 → A=8, B=19, s=2), equality of secrets across all presets, invalid parameters/keys, parameter changes, equal secrets from different key pairs, MITM secret relationships, message relay/tampering, and secure-mode behaviour.

## 6. Results and observations
- Valid inputs always give matching secrets.
- Different private-key pairs may yield the same secret (same `ab mod p−1`).
- In the MITM run the secrets of Alice and Bob differ, Mallory knows both, and Bob's ciphertext view is unreadable without her relay. Out-of-band fingerprint comparison would reveal the attack.
- Signature verification over the transcript rejects Mallory's substituted key.

## 7. Authentication and real-world practice
Defences: certificates (identity binding), signatures over handshake data, TLS 1.3 authenticated key exchange with ephemeral (EC)DH for forward secrecy, HKDF to derive keys, AEAD (AES-GCM, ChaCha20-Poly1305), and strict certificate/identity validation. A strong group alone does **not** prevent MITM.

## 8. Limitations
Tiny educational groups are breakable by brute force; the toy cipher is illustrative; secure mode uses X25519 (elliptic curve) rather than a finite-field group; the simulator displays private keys for teaching; no real network or PKI is implemented.

## 9. Conclusion
Diffie–Hellman lets parties establish a shared secret over an open channel, but safe deployment requires authentication, key derivation and authenticated encryption.

## 10. References
Diffie & Hellman (1976), *New Directions in Cryptography*; RFC 7748 (X25519); RFC 8446 (TLS 1.3); RFC 5869 (HKDF); `cryptography` library documentation.
