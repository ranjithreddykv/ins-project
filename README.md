# Diffie–Hellman Key Exchange Simulator
Secure shared-secret establishment and man-in-the-middle attack demonstration (Network Security assignment).

## Features
- Interactive Alice/Bob exchange with step-by-step equations and verification
- `secrets`-based random private keys; full input validation (prime p, primitive-root g, key ranges)
- Parameter experiments with a comparison table and a g^x mod p plot
- Alice–Mallory–Bob MITM simulation with a toy cipher (clearly labelled educational)
- Secure Mode: X25519 + HKDF-SHA256 + AES-256-GCM, plus an Ed25519 signature demo (`cryptography` library)
- Unit tests (pytest)

## Structure
| File | Role |
|---|---|
| `dh_core.py` | Educational maths, validation (stdlib only) |
| `mitm_simulation.py` | MITM attack + toy cipher |
| `secure_dh.py` | Library-based secure demo (separate from educational code) |
| `app.py` | Streamlit UI |
| `tests/` | pytest suites |
| `report/` | Project report and flowcharts |

## Install & run (Linux / WSL)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py        # opens http://localhost:8501
python -m pytest -q         # run tests
```
No external APIs are required.

## 5-minute demo script
1. **Key Exchange**: use p=23, g=5, a=6, b=15; show A=8, B=19, secret 2 on both sides.
2. **Experiments**: add rows with different keys/groups; show the "same secret, different keys" note.
3. **MITM**: click random keys; show two different secrets and Mallory reading the message.
4. **Secure Mode**: run the exchange, then the signature demo (MITM detected).

## Likely viva questions
- *Why is it secure?* Recovering `a` from `gᵃ mod p` is the discrete log problem.
- *Why do secrets match?* `(gᵇ)ᵃ = gᵃᵇ = (gᵃ)ᵇ`.
- *Does a bigger prime stop MITM?* No — authentication does.
- *Why exclude private key (p−1)/2?* It makes the public key p−1, giving a trivially weak secret.
- *Why X25519 in Secure Mode?* Standardized (RFC 7748), used in TLS 1.3, supported by `cryptography`; the finite-field maths is analogous.

## Security notice
Educational parameters (p ≤ 2³¹−1) are NOT secure. Never reuse `dh_core.py` or the toy cipher for real data.
