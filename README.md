# SecureBank — Secure Online Banking Web Application

**Course:** Web Application & Security (WAS) — Design & deploy a secure web application for a real-life scenario
**Scenario:** Online Banking System
**Student:** Hassaan Tole (24101C2006), B.E. Information Technology, Vidyalankar Institute of Technology

SecureBank lets customers open a savings account, sign in (optionally with an authenticator app), view balances and statements, and transfer money to other account holders. An administrator role audits security events, unlocks accounts and verifies ledger integrity. Every feature was built around the 13 web-application security principles below, and every control is proven by an automated attack test (`tests/test_security.py`, 40/40 passing).

## Stack
Python 3.12 · Flask 3 · SQLite · `cryptography` (AES-256-GCM) · Gunicorn · deployed on Render (free tier, HTTPS)

## Features
| Customer | Admin |
|---|---|
| Open account (with validated KYC fields) | View hash-chained audit log |
| Sign in + TOTP two-factor | Unlock locked accounts |
| Dashboard, account statement | Ledger/audit integrity verification |
| Two-step money transfer with step-up OTP | — (cannot view balances or move money) |
| Change password, sign out other devices | |

## Architecture
```
Browser ──HTTPS/TLS──► Render edge (HSTS) ──► Gunicorn ──► Flask app
                                                    │
        ┌────────────────────────────────────────────┼─────────────────────────┐
        │ before_request: load server-side session → CSRF/Origin check         │
        │ route: @login_required / @role_required → owned_account() (IDOR)     │
        │        → allow-list validation → business rules (limits, balance)    │
        │ data layer: parameterised SQL, AES-GCM for PII, HMAC for ledger      │
        │ after_request: security headers · errorhandler: generic page + id    │
        └──────────────────────────────────────────────────────────────────────┘
                                   │
                         SQLite (users, accounts, transactions,
                         sessions, pending_transfers, audit_log)
```

## Security principles → implementation
| # | Principle | How it is implemented | Where |
|---|---|---|---|
| 1 | Architecture & design | Layered (presentation → service checks → data); defence in depth; least privilege; fail-secure defaults | `app.py` |
| 2 | Deployment | Gunicorn (no dev server), HTTPS + HSTS, debug off, ProxyFix (1 hop), health check, non-root Docker user, secrets as env vars | `render.yaml`, `Dockerfile` |
| 3 | Input validation | Server-side allow-list regex per field; Decimal → integer paise; rejects negative/zero/exponent/over-limit; 16 KB body cap; parameterised SQL; Jinja auto-escaping | `security.py: clean, parse_amount` |
| 4 | Authentication | scrypt + salt; 12-char complexity policy + common-password list; lockout after 5 failures (15 min); per-IP rate limit; generic errors + dummy hash (no user enumeration); TOTP 2FA (RFC 6238) with replay protection; step-up OTP on transfers | `login`, `login_mfa`, `security.py` |
| 5 | Authorization | RBAC (customer/admin) with role from DB; object-level ownership check on every account (IDOR → 404); role fixed at signup (no mass assignment); separation of duties | `role_required`, `owned_account` |
| 6 | Configuration management | All keys from env, one key per purpose, fail-closed if missing in production, strict security headers (CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, COOP), server banner hidden | `config.py`, `harden()` |
| 7 | Sensitive data | Email, mobile, account number, TOTP secret encrypted at rest; masking (XXXX XXXX 1234, payee "Alice S."); no secrets in logs; `Cache-Control: no-store` | `Vault`, templates |
| 8 | Session management | 256-bit random token, only SHA-256 stored; HttpOnly + Secure + SameSite=Strict + `__Host-` cookie; regenerated at login/MFA (fixation); 10-min idle & 8-h absolute timeout; server-side logout; revoke other sessions; all sessions killed on password change | `start_session`, `load_session` |
| 9 | Cryptography | AES-256-GCM (random 96-bit nonce), scrypt, HMAC-SHA256, `secrets` CSPRNG, constant-time compares, TLS in transit — no custom crypto | `security.py` |
| 10 | Parameter manipulation | Source account re-verified; amounts/limits re-checked server-side; unguessable public ids; reviewed transfer stored server-side and confirmed by single-use, session-bound, 5-min nonce; atomic debit guarded by `balance >= amount` | `transfer`, `transfer_confirm` |
| 11 | Exception management | Global handler: generic page + incident reference; stack traces only in server log; DB rollback on failure | `handle_error` |
| 12 | Auditing | Append-only audit table of logins, failures, lockouts, MFA, transfers, account-number views, IDOR/CSRF/authz denials, admin actions; HMAC hash chain makes edits/deletions detectable | `audit()`, `/admin/integrity` |
| 13 | Logging | Structured JSON to stdout; control characters neutralised (log-injection safe); incident ids link user page ↔ log line | `SafeJsonFormatter`, `neutralise` |

## Run locally
```bash
pip install -r requirements.txt
python app.py                         # http://127.0.0.1:5000
python tests/test_security.py         # 40 attack tests
```
Demo logins: `alice / Alice@SecureBank1`, `bob / Bob@SecureBank1!`, `admin / Admin@SecureBank1`

## Deploy free on Render (≈3 minutes)
1. Push this folder to a GitHub repository.
2. On https://render.com → **New → Blueprint** → select the repo. `render.yaml` creates the web service on the free plan and generates all three secret keys.
3. Open the `https://securebank-xxxx.onrender.com` URL once the build is green.

The free tier sleeps after ~15 min idle (first request takes ~50 s to wake) and its disk is ephemeral, so demo data resets on redeploy — acceptable for a demo; production would use a managed PostgreSQL database.

## Attack tests (all pass)
SQL injection · XSS · CSRF (token + cross-origin) · IDOR · privilege escalation · mass assignment · amount tampering (negative, zero, 1e5, 0.001, overflow) · nonce tampering & replay · cross-user nonce reuse · brute-force lockout · rate limiting · user enumeration · session fixation · idle timeout · stolen cookie after logout · TOTP replay · weak passwords · data-at-rest encryption · error leakage · audit coverage · ledger/audit tamper detection.
