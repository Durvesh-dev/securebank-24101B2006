"""Data layer. Every query is parameterised (?) - no string concatenation - which
eliminates SQL injection."""
import secrets
import sqlite3
import time

from flask import current_app, g

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('customer','admin')),
    full_name TEXT NOT NULL,
    email_enc TEXT NOT NULL,
    phone_enc TEXT NOT NULL,
    totp_secret_enc TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_last_counter INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    public_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    acct_no_hash TEXT UNIQUE NOT NULL,
    acct_no_enc TEXT NOT NULL,
    last4 TEXT NOT NULL,
    kind TEXT NOT NULL,
    balance_paise INTEGER NOT NULL CHECK (balance_paise >= 0)
);
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    public_id TEXT UNIQUE NOT NULL,
    from_account INTEGER REFERENCES accounts(id),
    to_account INTEGER NOT NULL REFERENCES accounts(id),
    amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    stage TEXT NOT NULL CHECK (stage IN ('mfa','full')),
    csrf TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    ip TEXT, user_agent TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pending_transfers (
    nonce TEXT PRIMARY KEY,
    session_hash TEXT NOT NULL,
    from_account INTEGER NOT NULL,
    to_account INTEGER NOT NULL,
    amount_paise INTEGER NOT NULL,
    note TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    user_id INTEGER,
    username TEXT,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    ip TEXT,
    detail TEXT,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def new_public_id() -> str:
    # Unguessable identifiers in URLs instead of sequential ids (anti-enumeration).
    return secrets.token_hex(12)


def new_account_number(db) -> str:
    while True:
        n = "5021" + "".join(secrets.choice("0123456789") for _ in range(8))
        from security import sha256
        if not db.execute("SELECT 1 FROM accounts WHERE acct_no_hash=?", (sha256(n),)).fetchone():
            return n


def init_db(app, vault):
    from security import hash_password, sha256
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        # Demo seed data (DEMO_MODE). Real deployments create users via onboarding.
        seed = [
            ("admin", "Admin@SecureBank1", "admin", "Branch Administrator", "admin@securebank.test", "9000000001", None),
            ("alice", "Alice@SecureBank1", "customer", "Alice Sharma", "alice@example.com", "9876543210", 5_00_000_00),
            ("bob", "Bob@SecureBank1!", "customer", "Bob Verma", "bob@example.com", "9123456780", 75_000_00),
        ]
        now = int(time.time())
        for u, pw, role, name, email, phone, bal in seed:
            cur = db.execute(
                "INSERT INTO users (username,pw_hash,role,full_name,email_enc,phone_enc,created_at) VALUES (?,?,?,?,?,?,?)",
                (u, hash_password(pw), role, name, vault.encrypt(email), vault.encrypt(phone), now))
            if bal is not None:
                acct = new_account_number(db)
                db.execute(
                    "INSERT INTO accounts (public_id,user_id,acct_no_hash,acct_no_enc,last4,kind,balance_paise) VALUES (?,?,?,?,?,?,?)",
                    (new_public_id(), cur.lastrowid, sha256(acct), vault.encrypt(acct), acct[-4:], "Savings", bal))
