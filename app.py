"""app.py - Streamlit UI for the Diffie-Hellman Key Exchange Simulator.

UI rendering only: all maths lives in dh_core.py, the attack in mitm_simulation.py,
and the cryptography-library code in secure_dh.py.
Run:  streamlit run app.py
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

import dh_core as dh
import mitm_simulation as mitm

try:
    import secure_dh as sd
    SECURE_OK, SECURE_ERR = True, ""
except ImportError as exc:  # cryptography not installed
    SECURE_OK, SECURE_ERR = False, str(exc)

st.set_page_config(page_title="Diffie-Hellman Simulator", page_icon="🔐", layout="wide")
st.markdown("""<style>
.block-container{padding-top:1.5rem}
.card{border:1px solid #243049;border-radius:10px;padding:.8rem 1rem;background:#131c2e;margin-bottom:.5rem}
.alice{border-left:5px solid #3b82f6}.bob{border-left:5px solid #00e08a}.mallory{border-left:5px solid #ef4444}
.pub{text-align:center;padding-top:2rem;color:#f5b942}
</style>""", unsafe_allow_html=True)


# ------------------------------ helpers ------------------------------------- #
def clamp_key(key: str, default: int, p: int) -> None:
    """Keep a stored private key valid when p changes (widget bounds would otherwise crash)."""
    v = st.session_state.get(key, default)
    if not isinstance(v, int) or not (2 <= v <= p - 2) or v == (p - 1) // 2:
        v = next(x for x in (default, 2, 3, 4) if 2 <= x <= p - 2 and x != (p - 1) // 2)
    st.session_state[key] = v


def randomize(keys: list[str]) -> None:
    """Button callback: fresh random keys from `secrets`."""
    for k in keys:
        st.session_state[k] = dh.generate_private_key(st.session_state["_p"])


def key_input(label: str, key: str, p: int) -> int:
    return int(st.number_input(label, min_value=2, max_value=p - 2, step=1, key=key))


def party_card(css: str, title: str, lines: list[str]) -> None:
    st.markdown(f"<div class='card {css}'><b>{title}</b><br>" + "<br>".join(lines) + "</div>",
                unsafe_allow_html=True)


def plot_powers(p: int, g: int, pts: list[tuple[int, int, str, str]]) -> None:
    """Plot g^x mod p to show the 'random-looking' modular exponentiation."""
    xs = list(range(1, min(p, 400)))
    fig, ax = plt.subplots(figsize=(7, 3))
    ax.scatter(xs, [pow(g, x, p) for x in xs], s=8, color="#64748b", label=f"g^x mod {p}")
    for x, y, label, colour in pts:
        if x < 400:
            ax.scatter([x], [y], s=60, color=colour, label=label, zorder=3)
    ax.set_xlabel("exponent x"); ax.set_ylabel("g^x mod p"); ax.legend(fontsize=7)
    st.pyplot(fig); plt.close(fig)


# ------------------------------ sidebar ------------------------------------- #
st.sidebar.title("🔐 DH Simulator")
st.sidebar.caption("Educational parameters (small, NOT secure)")
source = st.sidebar.radio("Parameter source", ["Preset", "Custom"], horizontal=True)
if source == "Preset":
    p, g = dh.EDUCATIONAL_GROUPS[st.sidebar.selectbox("Group", list(dh.EDUCATIONAL_GROUPS))]
else:
    p = int(st.sidebar.number_input("Prime p", min_value=2, max_value=dh.MAX_EDU_PRIME, value=23, step=1))
    g = int(st.sidebar.number_input("Generator g", min_value=1, max_value=dh.MAX_EDU_PRIME, value=5, step=1))
params_ok = True
try:
    dh.validate_parameters(p, g)
    st.sidebar.success(f"Valid: p={p}, g={g}")
    st.session_state["_p"] = p
except dh.DHError as exc:
    params_ok = False
    st.sidebar.error(str(exc))
st.sidebar.info("Private keys are shown only because this is a labelled educational simulator.")

st.title("Diffie–Hellman Key Exchange Simulator")
st.caption("Secure shared-secret establishment and man-in-the-middle attack demonstration")
tabs = st.tabs(["Overview", "Key Exchange", "Parameter Experiments", "MITM Attack",
                "Secure Mode", "Algorithm & Theory", "Results & Limitations"])

# ------------------------------ Overview ------------------------------------ #
with tabs[0]:
    st.subheader("Objective")
    st.write("Show how two parties derive the same secret over a public channel without sending "
             "their private keys, and why *unauthenticated* Diffie–Hellman is vulnerable to a "
             "man-in-the-middle (MITM) attack.")
    st.markdown("**Protocol in one line:** `A = gᵃ mod p`, `B = gᵇ mod p`, shared secret `= gᵃᵇ mod p`.")
    st.graphviz_chart("""digraph{rankdir=LR;node[shape=box,style=filled,fillcolor="#131c2e",fontcolor=white,color="#00e08a"];
      edge[color="#f5b942",fontcolor="#f5b942"];
      UI[label="app.py\\nStreamlit UI"];Core[label="dh_core.py\\neducational maths"];
      M[label="mitm_simulation.py\\nAlice/Bob/Mallory"];S[label="secure_dh.py\\nX25519+HKDF+AES-GCM"];
      UI->Core;UI->M;UI->S;M->Core;}""")
    st.warning("Educational mode uses tiny parameters for hand-verification. Real security requires "
               "the Secure Mode tab (library-implemented, standardized primitives).")
    st.markdown("**Demo order (5 min):** Key Exchange → Experiments → MITM Attack → Secure Mode.")

# ------------------------------ Key exchange -------------------------------- #
with tabs[1]:
    if not params_ok:
        st.error("Fix the parameters in the sidebar first.")
    else:
        clamp_key("ke_a", 6, p); clamp_key("ke_b", 15, p)
        c1, c2 = st.columns(2)
        with c1:
            key_input("Alice's private key a", "ke_a", p)
        with c2:
            key_input("Bob's private key b", "ke_b", p)
        st.button("🎲 Generate random keys (secrets)", on_click=randomize, args=(["ke_a", "ke_b"],))
        try:
            ex = dh.run_exchange(p, g, st.session_state["ke_a"], st.session_state["ke_b"])
        except dh.DHError as exc:
            st.error(str(exc)); st.stop()
        st.latex(r"A = g^a \bmod p \quad B = g^b \bmod p \quad s_A = B^a \bmod p \quad s_B = A^b \bmod p")
        ca, cm, cb = st.columns([3, 2, 3])
        with ca:
            party_card("alice", "👩 Alice", [f"private a = {ex.a} (secret)", f"public A = {ex.A}",
                                              f"secret = B^a mod p = <b>{ex.alice_secret}</b>"])
        with cm:
            st.markdown(f"<div class='pub'>A = {ex.A} ➜<br>⬅ B = {ex.B}<br><small>public channel</small></div>",
                        unsafe_allow_html=True)
        with cb:
            party_card("bob", "👨 Bob", [f"private b = {ex.b} (secret)", f"public B = {ex.B}",
                                          f"secret = A^b mod p = <b>{ex.bob_secret}</b>"])
        if ex.secrets_match:
            st.success(f"✅ Shared secrets match: {ex.alice_secret}")
        else:
            st.error("❌ Shared secrets differ (this should never happen with valid inputs).")
        st.subheader("Step-by-step")
        for s in ex.steps:
            with st.expander(s.title, expanded=False):
                st.code(s.equation); st.write(s.explanation)
        st.info("Both get the same value because (gᵇ)ᵃ = gᵃᵇ = (gᵃ)ᵇ (mod p). The raw secret should be "
                "passed through a KDF before use as an encryption key.")

# ------------------------------ Experiments --------------------------------- #
with tabs[2]:
    if not params_ok:
        st.error("Fix the parameters in the sidebar first.")
    else:
        st.session_state.setdefault("history", [])
        clamp_key("ex_a", 3, p); clamp_key("ex_b", 7, p)
        c1, c2 = st.columns(2)
        with c1:
            key_input("Alice's private key", "ex_a", p)
        with c2:
            key_input("Bob's private key", "ex_b", p)
        b1, b2, b3 = st.columns(3)
        b1.button("🎲 Random keys", on_click=randomize, args=(["ex_a", "ex_b"],))
        if b2.button("➕ Add to comparison table"):
            st.session_state["history"].append(
                dh.experiment_row(p, g, st.session_state["ex_a"], st.session_state["ex_b"]))
        if b3.button("🗑 Clear table"):
            st.session_state["history"] = []
        st.caption("Tip: change the group in the sidebar, then add another row to compare parameters.")
        if st.session_state["history"]:
            st.dataframe(pd.DataFrame(st.session_state["history"]), use_container_width=True)
        a, b = st.session_state["ex_a"], st.session_state["ex_b"]
        row = dh.experiment_row(p, g, a, b)
        st.write(f"Current: A = {row['A']}, B = {row['B']}, shared secret = **{row['Alice secret']}**")
        plot_powers(p, g, [(a, row["A"], "A (Alice)", "#3b82f6"), (b, row["B"], "B (Bob)", "#00e08a")])
        st.subheader("Do different private keys always give a different secret?")
        st.write("No. The secret is g^(ab) mod p, which depends only on **ab mod (p−1)**. "
                 "Different key pairs with the same product (mod p−1) give the same number.")
        pairs = dh.find_same_secret_pairs(p, g, a, b)
        if pairs:
            st.write("Other (a, b) pairs with the same secret: " + ", ".join(f"({x}, {y})" for x, y in pairs))
        else:
            st.caption("Pair search is skipped for large p (or none exist).")

# ------------------------------ MITM ---------------------------------------- #
with tabs[3]:
    st.info("Simplified educational simulation. The 'cipher' is a toy XOR stream, not real "
            "encryption. Diffie–Hellman itself is a key-agreement protocol, not an encryption algorithm.")
    if not params_ok:
        st.error("Fix the parameters in the sidebar first.")
    else:
        for k, d in (("mi_a", 6), ("mi_b", 15), ("mi_ma", 3), ("mi_mb", 9)):
            clamp_key(k, d, p)
        c = st.columns(4)
        with c[0]: key_input("Alice a", "mi_a", p)
        with c[1]: key_input("Bob b", "mi_b", p)
        with c[2]: key_input("Mallory m₁ (to Alice)", "mi_ma", p)
        with c[3]: key_input("Mallory m₂ (to Bob)", "mi_mb", p)
        st.button("🎲 Random keys", on_click=randomize, args=(["mi_a", "mi_b", "mi_ma", "mi_mb"],), key="mi_rand")
        msg = st.text_input("Alice's message", "Transfer 500 to account 1234")
        tamper = st.text_input("Mallory's replacement message (optional)", "")
        try:
            r = mitm.simulate_mitm(p, g, st.session_state["mi_a"], st.session_state["mi_b"],
                                   st.session_state["mi_ma"], st.session_state["mi_mb"], msg,
                                   tamper or None)
        except (dh.DHError, ValueError) as exc:
            st.error(str(exc)); st.stop()
        st.graphviz_chart("""digraph{rankdir=LR;node[shape=box,style=filled,fontcolor=white];
          Alice[fillcolor="#1d4ed8"];Mallory[fillcolor="#b91c1c"];Bob[fillcolor="#047857"];
          Alice->Mallory[label="A (intercepted)"];Mallory->Bob[label="M₂ (forged, posing as Alice)"];
          Bob->Mallory[label="B (intercepted)"];Mallory->Alice[label="M₁ (forged, posing as Bob)"];}""")
        ca, cm, cb = st.columns(3)
        with ca:
            party_card("alice", "👩 Alice", [f"sent A = {r.A}", f"received M₁ = {r.forged_to_alice}",
                                              f"secret = <b>{r.alice_secret}</b> (shared with Mallory!)"])
        with cm:
            party_card("mallory", "😈 Mallory", [f"secret with Alice = {r.mallory_secret_with_alice}",
                                                  f"secret with Bob = {r.mallory_secret_with_bob}"])
        with cb:
            party_card("bob", "👨 Bob", [f"sent B = {r.B}", f"received M₂ = {r.forged_to_bob}",
                                          f"secret = <b>{r.bob_secret}</b> (shared with Mallory!)"])
        if r.secrets_differ:
            st.error("⚠ Attack succeeded: Alice and Bob hold DIFFERENT secrets, each shared with Mallory.")
        else:
            st.warning("Secrets coincide by chance in this tiny group; Mallory still knows both. Try other keys.")
        st.subheader("Message relay")
        st.code(f"Alice  -> ciphertext {r.ciphertext_from_alice.hex()}\n"
                f"Mallory decrypts   : {r.mallory_read!r}\n"
                f"Mallory forwards   : {r.forwarded_message!r}{'  (TAMPERED)' if r.tampered else ''}\n"
                f"Bob    receives    : {r.bob_received!r}\n"
                f"If Alice's original ciphertext reached Bob directly he would see: {r.bob_decrypt_of_original!r}")
        fa, fb = r.fingerprints()
        st.write(f"Secret fingerprints - Alice: `{fa}`, Bob: `{fb}`. "
                 + ("Comparing them out-of-band would expose the attack." if r.detectable_by_fingerprint
                    else "Identical here by chance."))
        st.info("Real systems derive keys with HKDF and use authenticated encryption; the defence "
                "against MITM is authenticating the key exchange (see Secure Mode).")

# ------------------------------ Secure mode --------------------------------- #
with tabs[4]:
    st.subheader("Secure implementation (cryptography library)")
    st.write("X25519 key agreement (the elliptic-curve form of DH used in TLS 1.3) → HKDF-SHA256 → "
             "AES-256-GCM. Fully separate from the educational code; nothing is implemented from scratch.")
    if not SECURE_OK:
        st.error(f"The `cryptography` package is missing: {SECURE_ERR}. Run `pip install -r requirements.txt`.")
    else:
        text = st.text_input("Message to protect", "Hello Bob, this is Alice.", key="sec_msg")
        if st.button("Run secure exchange") and text:
            res = sd.run_secure_exchange(text)
            st.code(f"Alice public : {res.alice_public_hex}\nBob public   : {res.bob_public_hex}\n"
                    f"Session-key fingerprint (key not shown): {res.key_fingerprint}\n"
                    f"AES-GCM blob : {res.ciphertext_hex}")
            (st.success if res.keys_match else st.error)(f"Keys match: {res.keys_match}. Decrypted: {res.decrypted!r}")
            (st.success if res.tamper_detected else st.error)(
                "Flipping one ciphertext bit was rejected by AES-GCM (integrity protected)."
                if res.tamper_detected else "Tampering NOT detected.")
        st.warning("A strong group does not stop a MITM by itself. Without authentication Mallory can still "
                   "run two separate secure exchanges.")
        st.subheader("Conceptual: authenticating the handshake with signatures (Ed25519)")
        if st.button("Run signature demo"):
            sh = sd.signed_handshake_demo()
            st.success(f"Bob's genuine signature verifies: {sh.honest_signature_valid}")
            (st.success if not sh.mitm_signature_valid else st.error)(
                f"Mallory's forged value verifies: {sh.mitm_signature_valid} → MITM detected")
            st.write(sh.explanation)
    st.subheader("Unauthenticated vs authenticated key exchange")
    st.table(pd.DataFrame({
        "Aspect": ["Peer identity", "MITM", "Typical use", "Key derivation", "Data protection"],
        "Unauthenticated DH": ["Unknown", "Possible", "Teaching demo", "None / ad hoc", "None"],
        "Authenticated (TLS 1.3)": ["Certificates + signatures over the transcript", "Detected (handshake fails)",
                                    "HTTPS, VPNs", "HKDF", "AES-GCM / ChaCha20-Poly1305"]}))

# ------------------------------ Theory -------------------------------------- #
with tabs[5]:
    st.subheader("Equations")
    st.latex(r"A=g^a \bmod p,\quad B=g^b \bmod p,\quad s=B^a=A^b=g^{ab}\bmod p")
    st.subheader("Algorithm")
    st.markdown("""1. Agree on public prime `p` and generator `g`.
2. Alice picks secret `a`, computes `A = gᵃ mod p`; Bob picks `b`, computes `B = gᵇ mod p`.
3. They exchange `A` and `B` over the public channel.
4. Alice computes `Bᵃ mod p`; Bob computes `Aᵇ mod p`.
5. Both hold `gᵃᵇ mod p`; derive keys with a KDF.""")
    st.markdown("**Security basis:** Discrete Logarithm / Computational Diffie–Hellman problem. "
                "**Why g is a primitive root:** it makes public keys range over the whole group.")
    st.graphviz_chart("""digraph{node[shape=box,style=filled,fillcolor="#131c2e",fontcolor=white];
      S[label="Choose p, g",shape=oval];K[label="Alice: a   Bob: b"];P[label="A = g^a mod p\\nB = g^b mod p"];
      X[label="Exchange A, B"];C[label="s = B^a mod p  |  s = A^b mod p"];V[label="Secrets equal?",shape=diamond];
      OK[label="Derive keys (HKDF)",shape=oval];F[label="Error",shape=oval];
      S->K->P->X->C->V;V->OK[label="yes"];V->F[label="no"];}""")

# ------------------------------ Results ------------------------------------- #
with tabs[6]:
    st.subheader("Observations")
    st.markdown("""- Both parties always obtain identical secrets with valid inputs.
- Changing a private key changes the matching public key; changing `p` or `g` changes everything.
- Different key pairs can produce the same secret (same `ab mod p−1`).
- With unauthenticated DH, Mallory ends up with one secret per victim and can read/modify traffic.""")
    st.subheader("Limitations")
    st.markdown("""- Educational parameters are tiny: the discrete log can be brute-forced instantly.
- The toy cipher in the MITM tab is for illustration only.
- Basic DH gives no authentication; forward secrecy needs fresh ephemeral keys.
- The simulator displays private keys, which a real system never would.
- Secure Mode demonstrates X25519, not a finite-field group; the maths is analogous.""")
    st.subheader("Conclusion")
    st.write("Diffie–Hellman establishes shared secrets over open channels, but only authenticated "
             "exchange (certificates, signatures), HKDF and authenticated encryption make it safe in practice.")
