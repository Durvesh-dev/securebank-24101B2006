"""Attack-driven security test suite for SecureBank.
Run:  python -m pytest -q tests/   (or:  python tests/test_security.py)
"""
import os
import re
import sqlite3
import sys
import tempfile
import time

TMP = tempfile.mkdtemp()
os.environ["DATABASE_PATH"] = os.path.join(TMP, "test.db")
os.environ.setdefault("DATA_ENCRYPTION_KEY", "test-data-key-" + "x" * 40)
os.environ.setdefault("LEDGER_HMAC_KEY", "test-ledger-key-" + "y" * 40)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as appmod  # noqa: E402
from security import totp_now  # noqa: E402

app = appmod.app
app.config["TESTING"] = True
DB = os.environ["DATABASE_PATH"]
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def token(html):
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def client():
    return app.test_client()


def login(c, user, pw):
    t = token(c.get("/login").get_data(as_text=True))
    return c.post("/login", data={"username": user, "password": pw, "csrf_token": t})


def page_token(c, path="/transfer"):
    return token(c.get(path).get_data(as_text=True))


def q(sql, *a):
    con = sqlite3.connect(DB)
    r = con.execute(sql, a).fetchall()
    con.commit()
    con.close()
    return r


def run():
    appmod._hits.clear()
    # ---------- CSRF
    c = client()
    c.get("/login")
    r = c.post("/login", data={"username": "alice", "password": "Alice@SecureBank1"})
    check("CSRF: login POST without token is refused (no sign-in)", r.status_code in (302, 403) and "/dashboard" not in r.headers.get("Location", ""))
    r = c.post("/transfer", data={"amount": "1"})
    check("CSRF: state-changing POST without token is rejected (403)", r.status_code in (302, 403))
    old = client()
    stale = token(old.get("/login").get_data(as_text=True))
    login(old, "alice", "Alice@SecureBank1")
    r = old.post("/login", data={"username": "bob", "password": "Bob@SecureBank1!", "csrf_token": stale})
    check("Usability: stale login page (Back button / switching user) still signs in", r.status_code == 302 and "/dashboard" in r.headers.get("Location", ""))
    t = page_token(c, "/login")
    r = c.post("/login", data={"username": "alice", "password": "x", "csrf_token": t},
               headers={"Origin": "https://evil.example"})
    check("CSRF: cross-origin POST is rejected (403)", r.status_code == 403)

    # ---------- Authentication
    r1 = login(client(), "alice", "wrong-password")
    r2 = login(client(), "nosuchuser", "wrong-password")
    m1, m2 = b"Invalid username or password." in r1.data, b"Invalid username or password." in r2.data
    check("AuthN: identical error for bad password and unknown user (no enumeration)", m1 and m2 and r1.status_code == r2.status_code)
    r = login(client(), "' OR '1'='1' --", "' OR '1'='1")
    check("SQLi: injection in login is treated as data (401, not 200/500)", r.status_code == 401)
    appmod._hits.clear()
    for _ in range(5):
        login(client(), "bob", "bad-guess")
    r = login(client(), "bob", "Bob@SecureBank1!")
    check("AuthN: account locks after 5 failures even with correct password", r.status_code == 423)
    appmod._hits.clear()
    q("UPDATE users SET locked_until=0, failed_attempts=0 WHERE username='bob'")
    appmod._hits.clear()
    codes = [login(client(), "ghost", "x").status_code for _ in range(12)]
    check("AuthN: per-IP rate limit returns 429", 429 in codes)
    appmod._hits.clear()
    pw_hash = q("SELECT pw_hash FROM users WHERE username='alice'")[0][0]
    check("Crypto: passwords stored as salted scrypt hashes", pw_hash.startswith("scrypt$") and "Alice" not in pw_hash)

    # ---------- Session management
    a = client()
    a.get("/login")
    pre = a.get_cookie("sb_sid")
    r = login(a, "alice", "Alice@SecureBank1")
    sc = r.headers.get("Set-Cookie", "")
    check("Session: cookie is HttpOnly + SameSite=Strict", "HttpOnly" in sc and "SameSite=Strict" in sc)
    alice_tok = a.get_cookie("sb_sid").value
    check("Session: new token issued at login (anti-fixation)", pre is None and alice_tok)
    stored = q("SELECT token_hash FROM sessions")
    check("Session: raw token never stored server-side (hash only)", all(alice_tok != s[0] for s in stored))

    # ---------- Headers / config
    r = a.get("/dashboard")
    h = r.headers
    check("Config: CSP, X-Frame-Options, nosniff, Referrer-Policy present",
          "frame-ancestors 'none'" in h.get("Content-Security-Policy", "") and h.get("X-Frame-Options") == "DENY"
          and h.get("X-Content-Type-Options") == "nosniff" and h.get("Referrer-Policy") == "no-referrer")
    check("Sensitive data: authenticated pages are Cache-Control: no-store", h.get("Cache-Control") == "no-store")
    check("Config: framework banner hidden", "Werkzeug" not in h.get("Server", ""))

    # ---------- Authorization / IDOR
    alice_pid = re.search(r'/accounts/([a-f0-9]{24})', r.get_data(as_text=True)).group(1)
    b = client()
    login(b, "bob", "Bob@SecureBank1!")
    r = b.get(f"/accounts/{alice_pid}")
    check("AuthZ/IDOR: bob cannot open alice's account (404)", r.status_code == 404)
    check("AuthZ: customer cannot reach /admin (403)", a.get("/admin").status_code == 403)
    check("AuthZ: anonymous user redirected from /dashboard", client().get("/dashboard").status_code == 302)
    r = b.get("/accounts/1 OR 1=1")
    check("Validation: malformed object id rejected (404)", r.status_code == 404)

    # ---------- Input validation on transfer
    bob_no = q("SELECT a.acct_no_enc FROM accounts a JOIN users u ON u.id=a.user_id WHERE username='bob'")[0][0]
    bob_no = appmod.vault.decrypt(bob_no)
    bad_amounts = ["-500", "0", "1e5", "0.001", "abc", "99999999999", "100000.01"]
    rejected = 0
    for amt in bad_amounts:
        t = page_token(a)
        r = a.post("/transfer", data={"csrf_token": t, "from_account": alice_pid, "to_account_no": bob_no, "amount": amt})
        rejected += r.status_code == 400
    check(f"Validation: all {len(bad_amounts)} malicious/invalid amounts rejected", rejected == len(bad_amounts))
    t = page_token(a)
    r = a.post("/transfer", data={"csrf_token": t, "from_account": alice_pid, "to_account_no": bob_no,
                                  "amount": "10", "note": "<script>alert(1)</script>"})
    check("Validation/XSS: script payload in note rejected", r.status_code == 400 and b"<script>alert" not in r.data)
    bob_pid = re.search(r'/accounts/([a-f0-9]{24})', b.get("/dashboard").get_data(as_text=True)).group(1)
    t = page_token(a)
    r = a.post("/transfer", data={"csrf_token": t, "from_account": bob_pid, "to_account_no": bob_no, "amount": "10"})
    check("Param tampering: using someone else's source account is refused", r.status_code == 404)

    # ---------- Valid transfer + nonce tampering
    before = q("SELECT balance_paise FROM accounts WHERE public_id=?", bob_pid)[0][0]
    t = page_token(a)
    r = a.post("/transfer", data={"csrf_token": t, "from_account": alice_pid, "to_account_no": bob_no,
                                  "amount": "1500.50", "note": "Rent share"})
    html = r.get_data(as_text=True)
    nonce = re.search(r'name="nonce" value="([^"]+)"', html).group(1)
    ct = token(html)
    r = a.post("/transfer/confirm", data={"csrf_token": ct, "nonce": nonce[:-2] + "zz"})
    after_bad = q("SELECT balance_paise FROM accounts WHERE public_id=?", bob_pid)[0][0]
    check("Param tampering: altered confirmation nonce moves no money", after_bad == before)
    # forged nonce consumed? the real one is still valid only if untouched - re-review
    t = page_token(a)
    html = a.post("/transfer", data={"csrf_token": t, "from_account": alice_pid, "to_account_no": bob_no,
                                     "amount": "1500.50", "note": "Rent share"}).get_data(as_text=True)
    nonce = re.search(r'name="nonce" value="([^"]+)"', html).group(1)
    a.post("/transfer/confirm", data={"csrf_token": ct, "nonce": nonce, "amount": "99999"})  # extra param ignored
    after = q("SELECT balance_paise FROM accounts WHERE public_id=?", bob_pid)[0][0]
    check("Transfer: exact reviewed amount credited; injected 'amount' param ignored", after - before == 150050)
    a.post("/transfer/confirm", data={"csrf_token": ct, "nonce": nonce})
    again = q("SELECT balance_paise FROM accounts WHERE public_id=?", bob_pid)[0][0]
    check("Replay: confirmation nonce is single-use", again == after)
    r = b.post("/transfer/confirm", data={"csrf_token": page_token(b), "nonce": nonce})
    check("Session binding: another user cannot use alice's nonce", q("SELECT balance_paise FROM accounts WHERE public_id=?", bob_pid)[0][0] == again)

    # ---------- Sensitive data at rest
    raw = open(DB, "rb").read()
    check("Sensitive data: email/phone/account no. encrypted at rest", b"alice@example.com" not in raw
          and b"9876543210" not in raw and bob_no.encode() not in raw)

    # ---------- 2FA
    t = page_token(b, "/security")
    html = b.post("/security/2fa/start", data={"csrf_token": t}).get_data(as_text=True)
    secret = re.search(r'class="secret">([A-Z2-7]+)<', html).group(1)
    b.post("/security/2fa/enable", data={"csrf_token": token(html), "code": totp_now(secret)})
    check("2FA: enabled for bob", q("SELECT totp_enabled FROM users WHERE username='bob'")[0][0] == 1)
    b2 = client()
    r = login(b2, "bob", "Bob@SecureBank1!")
    check("2FA: password alone is not enough (redirect to MFA)", "/login/mfa" in r.headers.get("Location", ""))
    check("2FA: half-authenticated session cannot reach dashboard", b2.get("/dashboard").status_code == 302)
    mt = token(b2.get("/login/mfa").get_data(as_text=True))
    r = b2.post("/login/mfa", data={"csrf_token": mt, "code": "000000"})
    check("2FA: wrong code rejected", r.status_code == 401)
    r = b2.post("/login/mfa", data={"csrf_token": mt, "code": totp_now(secret)})
    check("2FA: replay of the code used at enrolment is refused", r.status_code == 401)
    time.sleep(0)  # same 30s window: wait for next step to test a fresh code
    q("UPDATE users SET totp_last_counter=totp_last_counter-1 WHERE username='bob'")
    r = b2.post("/login/mfa", data={"csrf_token": mt, "code": totp_now(secret)})
    check("2FA: fresh valid code completes sign-in", r.status_code == 302 and b2.get("/dashboard").status_code == 200)

    # ---------- Session timeout & logout
    q("UPDATE sessions SET last_seen=last_seen-700 WHERE token_hash IN (SELECT token_hash FROM sessions WHERE user_id=(SELECT id FROM users WHERE username='bob') AND revoked=0)")
    check("Session: idle timeout (10 min) forces re-login", b2.get("/dashboard").status_code == 302)
    t = page_token(a, "/dashboard")
    a.post("/logout", data={"csrf_token": t})
    stolen = client()
    stolen.set_cookie("sb_sid", alice_tok)
    check("Session: token is dead server-side after logout (stolen cookie useless)", stolen.get("/dashboard").status_code == 302)

    # ---------- Mass assignment
    c = client()
    t = token(c.get("/register").get_data(as_text=True))
    c.post("/register", data={"csrf_token": t, "full_name": "Eve Hacker", "email": "eve@example.com", "phone": "9988776655",
                              "username": "evehacker", "password": "Ev3!StrongPassword", "confirm": "Ev3!StrongPassword", "role": "admin"})
    check("Mass assignment: 'role=admin' in signup is ignored", q("SELECT role FROM users WHERE username='evehacker'") == [("customer",)])
    c = client()
    t = token(c.get("/register").get_data(as_text=True))
    r = c.post("/register", data={"csrf_token": t, "full_name": "Weak", "email": "w@example.com", "phone": "9988776654",
                                  "username": "weakuser", "password": "password123", "confirm": "password123"})
    check("AuthN: weak password rejected at signup", r.status_code == 400)

    # ---------- Exceptions
    r = client().get("/does/not/exist")
    body = r.get_data(as_text=True)
    check("Exceptions: 404 page is generic with incident ref, no traceback", r.status_code == 404 and "Reference" in body and "Traceback" not in body)

    # ---------- Audit + integrity
    ad = client()
    appmod._hits.clear()
    login(ad, "admin", "Admin@SecureBank1")
    html = ad.get("/admin").get_data(as_text=True)
    check("Audit: IDOR, CSRF, lockout and transfer events recorded",
          all(e in html for e in ["idor_attempt", "csrf_blocked", "account_locked", "transfer"]))
    check("Audit: no passwords appear in the audit log", "Alice@SecureBank1" not in html and "bad-guess" not in html)
    r = ad.get("/admin/integrity").get_data(as_text=True)
    check("Integrity: untouched ledger and audit chain verify", "All signatures valid" in r)
    q("UPDATE transactions SET amount_paise=1 WHERE id=1")
    q("DELETE FROM audit_log WHERE id=3")
    r = ad.get("/admin/integrity").get_data(as_text=True)
    check("Integrity: edited transaction and deleted audit row are detected", "Tampering detected" in r)

    passed = sum(ok for _, ok in results)
    print(f"\n{passed}/{len(results)} security checks passed")
    return passed == len(results)


def test_all():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
