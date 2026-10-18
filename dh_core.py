"""dh_core.py - Educational Diffie-Hellman mathematics (standard library only).

WARNING: The parameters handled here are deliberately SMALL so that every step can
be verified by hand. They provide NO real security. See secure_dh.py for the
secure-mode demonstration that uses the `cryptography` library.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Largest prime accepted in educational mode. Keeping it small lets us factor p-1
# by trial division to check the generator. Real DH uses >= 2048-bit primes.
MAX_EDU_PRIME = 2**31 - 1

# Pre-verified educational groups: name -> (p, g). g is a primitive root of p.
EDUCATIONAL_GROUPS: Dict[str, Tuple[int, int]] = {
    "Tiny - textbook (p=23, g=5)": (23, 5),
    "Small (p=47, g=5)": (47, 5),
    "Small (p=97, g=5)": (97, 5),
    "Medium (p=467, g=2)": (467, 2),
    "Medium (p=1019, g=2)": (1019, 2),
}


class DHError(ValueError):
    """Base class for all validation errors raised by this module."""


class InvalidParameterError(DHError):
    """Raised when the public prime p or generator g is unacceptable."""


class InvalidKeyError(DHError):
    """Raised when a private or public key is out of range or of wrong type."""


# --------------------------------------------------------------------------- #
# Number theory helpers
# --------------------------------------------------------------------------- #
def _is_int(x: object) -> bool:
    """True for real integers (bool is rejected on purpose)."""
    return isinstance(x, int) and not isinstance(x, bool)


def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin primality test (exact for n < 3.3e24)."""
    if not _is_int(n) or n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for q in small:
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime_factors(n: int) -> List[int]:
    """Distinct prime factors of n by trial division (n is small here)."""
    factors, d = [], 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def is_primitive_root(g: int, p: int) -> bool:
    """True if g generates the whole multiplicative group Z_p* (p prime)."""
    if not is_prime(p) or not (1 < g < p):
        return False
    return all(pow(g, (p - 1) // q, p) != 1 for q in prime_factors(p - 1))


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
def validate_parameters(p: int, g: int) -> None:
    """Raise InvalidParameterError unless (p, g) are acceptable educational values."""
    if not _is_int(p) or not _is_int(g):
        raise InvalidParameterError("p and g must be integers.")
    if p < 5:
        raise InvalidParameterError("p must be at least 5.")
    if p > MAX_EDU_PRIME:
        raise InvalidParameterError(
            f"p must be <= {MAX_EDU_PRIME} in educational mode (use Secure Mode for real security)."
        )
    if not is_prime(p):
        raise InvalidParameterError(f"p = {p} is not prime.")
    if not (2 <= g <= p - 2):
        raise InvalidParameterError(f"g must satisfy 2 <= g <= p-2 (here 2 <= g <= {p - 2}).")
    if not is_primitive_root(g, p):
        raise InvalidParameterError(
            f"g = {g} is not a primitive root (generator) of p = {p}; it would reach only a subset of values."
        )


def validate_private_key(x: int, p: int) -> None:
    """Private keys must be integers in [2, p-2], excluding (p-1)/2.

    For a primitive root g, x = (p-1)/2 gives g^x = p-1 (the order-2 element), which
    collapses the shared secret to 1 or p-1 - a trivially weak value.
    """
    if not _is_int(x):
        raise InvalidKeyError("Private key must be an integer.")
    if not (2 <= x <= p - 2):
        raise InvalidKeyError(f"Private key must satisfy 2 <= x <= {p - 2}; got {x}.")
    if x == (p - 1) // 2:
        raise InvalidKeyError(f"Private key {x} = (p-1)/2 is weak (public key would be p-1); choose another.")


def validate_public_key(y: int, p: int) -> None:
    """Reject public values 0, 1 and p-1 (trivial / small-subgroup values) and out-of-range input."""
    if not _is_int(y):
        raise InvalidKeyError("Public key must be an integer.")
    if not (2 <= y <= p - 2):
        raise InvalidKeyError(f"Public key must satisfy 2 <= y <= {p - 2}; got {y}.")


# --------------------------------------------------------------------------- #
# Core protocol
# --------------------------------------------------------------------------- #
def generate_private_key(p: int) -> int:
    """Random private key in [2, p-2] using the CSPRNG-backed `secrets` module."""
    if not _is_int(p) or p < 5:
        raise InvalidParameterError("p must be an integer >= 5.")
    while True:
        x = secrets.randbelow(p - 3) + 2  # uniform in [2, p-2]
        if x != (p - 1) // 2:             # redraw the one weak exponent
            return x


def compute_public_key(g: int, private: int, p: int) -> int:
    """Public key = g^private mod p."""
    validate_private_key(private, p)
    return pow(g, private, p)


def compute_shared_secret(peer_public: int, private: int, p: int) -> int:
    """Shared secret = peer_public^private mod p."""
    validate_private_key(private, p)
    validate_public_key(peer_public, p)
    return pow(peer_public, private, p)


@dataclass(frozen=True)
class Step:
    """One explained stage of the computation, for display in the UI."""
    title: str
    equation: str
    explanation: str


@dataclass(frozen=True)
class DHExchange:
    """Complete record of one Diffie-Hellman run (educational: includes private keys)."""
    p: int
    g: int
    a: int
    b: int
    A: int
    B: int
    alice_secret: int
    bob_secret: int
    steps: List[Step] = field(default_factory=list, compare=False)

    @property
    def secrets_match(self) -> bool:
        return self.alice_secret == self.bob_secret


def explain_steps(p: int, g: int, a: int, b: int, A: int, B: int, sa: int, sb: int) -> List[Step]:
    """Build numbered, human-readable explanations using the actual values."""
    return [
        Step("1. Public parameters", f"p = {p},  g = {g}",
             "Alice and Bob openly agree on a prime p and a generator g. These are not secret."),
        Step("2. Private keys", f"a = {a} (Alice),  b = {b} (Bob)",
             "Each party picks a secret exponent and never sends it over the channel."),
        Step("3. Public keys", f"A = g^a mod p = {g}^{a} mod {p} = {A}\n"
                               f"B = g^b mod p = {g}^{b} mod {p} = {B}",
             "Modular exponentiation is easy forward, but recovering the exponent is the discrete logarithm problem."),
        Step("4. Exchange", f"Alice -> Bob: A = {A}\nBob -> Alice: B = {B}",
             "Only A and B cross the public channel. An eavesdropper sees p, g, A, B."),
        Step("5. Shared secrets", f"Alice: B^a mod p = {B}^{a} mod {p} = {sa}\n"
                                  f"Bob:   A^b mod p = {A}^{b} mod {p} = {sb}",
             "Each side combines the other's public key with its own private key."),
        Step("6. Why they match", f"(g^b)^a = g^(ab) = (g^a)^b  (mod p)",
             "Exponents multiply commutatively, so both sides compute g^(ab) mod p."),
    ]


def run_exchange(p: int, g: int, a: Optional[int] = None, b: Optional[int] = None) -> DHExchange:
    """Run a full exchange. Missing private keys are generated with `secrets`."""
    validate_parameters(p, g)
    a = generate_private_key(p) if a is None else a
    b = generate_private_key(p) if b is None else b
    A = compute_public_key(g, a, p)
    B = compute_public_key(g, b, p)
    sa = compute_shared_secret(B, a, p)   # Alice's view
    sb = compute_shared_secret(A, b, p)   # Bob's view (computed independently)
    return DHExchange(p, g, a, b, A, B, sa, sb, explain_steps(p, g, a, b, A, B, sa, sb))


# --------------------------------------------------------------------------- #
# Experimentation helpers
# --------------------------------------------------------------------------- #
SCAN_LIMIT = 5000  # brute-force scans are only done for small p


def experiment_row(p: int, g: int, a: int, b: int) -> Dict[str, object]:
    """One row for the experiment comparison table."""
    ex = run_exchange(p, g, a, b)
    return {"p": p, "g": g, "a": a, "b": b, "A": ex.A, "B": ex.B,
            "Alice secret": ex.alice_secret, "Bob secret": ex.bob_secret,
            "Match": "Yes" if ex.secrets_match else "No"}


def find_same_secret_pairs(p: int, g: int, a: int, b: int, limit: int = 6) -> List[Tuple[int, int]]:
    """Other (a', b') pairs that give the SAME shared secret.

    Because g^(ab) depends only on ab mod (p-1) (Fermat), different private-key
    pairs with the same product mod (p-1) yield the same numerical secret.
    """
    validate_parameters(p, g)
    validate_private_key(a, p)
    validate_private_key(b, p)
    if p > SCAN_LIMIT:
        return []
    target, n, found = (a * b) % (p - 1), p - 1, []
    weak = (p - 1) // 2
    for a2 in range(2, p - 1):
        if a2 == weak:
            continue
        for b2 in range(2, p - 1):
            if b2 != weak and (a2, b2) != (a, b) and (a2 * b2) % n == target:
                found.append((a2, b2))
                if len(found) >= limit:
                    return found
    return found
