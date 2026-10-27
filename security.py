"""Security primitives: hashing, encryption, signing, TOTP, validation, logging."""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import struct
import time
from decimal import Decimal, InvalidOperation

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------- passwords
# scrypt is a memory-hard KDF (resists GPU cracking). Each hash has a random salt.
_SCRYPT = dict(n=2 ** 14, r=8, p=1, dklen=32)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return "scrypt$%s$%s" % (base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64), **_SCRYPT)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))  # constant time
    except Exception:
        return False


# Used when the username does not exist so the response time is identical
# (prevents username enumeration by timing).
DUMMY_HASH = hash_password(secrets.token_hex(16))

COMMON_PASSWORDS = {
    "password", "password123", "123456789", "qwerty123", "iloveyou", "admin123",
    "welcome123", "letmein", "passw0rd", "password@123", "india@123", "abc@12345",
}


def password_problems(password: str, username: str = "") -> list:
    problems = []
    if len(password) < 12:
        problems.append("at least 12 characters")
    if len(password) > 128:
        problems.append("at most 128 characters")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a symbol")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not be a common password")
    if username and username.lower() in password.lower():
        problems.append("not contain your username")
    return problems


# ---------------------------------------------------------------- encryption at rest
class Vault:
    """AES-256-GCM authenticated encryption for sensitive fields (PII, TOTP secrets,
    full account numbers). A fresh 96-bit nonce per value; tampering is detected."""

    def __init__(self, key: bytes):
        self._aes = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, plaintext.encode(), b"securebank")
        return base64.b64encode(nonce + ct).decode()

    def decrypt(self, token: str) -> str:
        raw = base64.b64decode(token)
        return self._aes.decrypt(raw[:12], raw[12:], b"securebank").decode()


def sign(key: bytes, *parts) -> str:
    msg = "|".join(str(p) for p in parts).encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------------------------------------------------------------- TOTP (RFC 6238)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def totp_now(secret_b32: str, at=None) -> str:
    return _hotp(secret_b32, int((at or time.time()) // 30))


def verify_totp(secret_b32: str, code: str, last_counter: int):
    """Returns the matched counter, or None. Accepts +/-1 step for clock drift
    and refuses counters already used (replay protection)."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    now = int(time.time() // 30)
    for c in (now - 1, now, now + 1):
        if c > (last_counter or 0) and hmac.compare_digest(_hotp(secret_b32, c), code):
            return c
    return None


# ---------------------------------------------------------------- input validation
# Allow-list (whitelist) validation: describe what IS valid, reject everything else.
RULES = {
    "username": re.compile(r"[a-z][a-z0-9_]{3,19}"),
    "full_name": re.compile(r"[A-Za-z][A-Za-z .'-]{1,59}"),
    "email": re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,10}"),
    "phone": re.compile(r"[6-9]\d{9}"),                     # Indian mobile
    "account_no": re.compile(r"\d{12}"),
    "public_id": re.compile(r"[a-f0-9]{24}"),
    "note": re.compile(r"[A-Za-z0-9 .,'/()-]{0,60}"),
    "otp": re.compile(r"\d{6}"),
}


class ValidationError(ValueError):
    pass


def clean(field: str, value, required=True) -> str:
    value = (value or "").strip()
    if not value and not required:
        return ""
    if field == "username":
        value = value.lower()
    if not RULES[field].fullmatch(value):
        raise ValidationError(f"Invalid {field.replace('_', ' ')}.")
    return value


def parse_amount(raw: str, max_paise: int) -> int:
    """Parse rupees into integer paise. Decimal avoids float rounding errors;
    rejects negatives, zero, >2 decimals, exponents and absurd values."""
    raw = (raw or "").strip().replace(",", "")
    if not re.fullmatch(r"\d{1,9}(\.\d{1,2})?", raw):
        raise ValidationError("Enter an amount like 1500 or 1500.50.")
    try:
        paise = int(Decimal(raw) * 100)
    except InvalidOperation:
        raise ValidationError("Invalid amount.")
    if paise <= 0:
        raise ValidationError("Amount must be greater than zero.")
    if paise > max_paise:
        raise ValidationError(f"Amount exceeds the per-transaction limit of {rupees(max_paise)}.")
    return paise


def rupees(paise: int) -> str:
    sign_ = "-" if paise < 0 else ""
    r, p = divmod(abs(paise), 100)
    s = str(r)
    if len(s) > 3:  # Indian digit grouping 1,00,000
        head, tail = s[:-3], s[-3:]
        head = ",".join([head[max(i - 2, 0):i] for i in range(len(head), 0, -2)][::-1])
        s = head + "," + tail
    return f"{sign_}₹{s}.{p:02d}"


def mask_account(last4: str) -> str:
    return "XXXX XXXX " + last4


# ---------------------------------------------------------------- logging
class SafeJsonFormatter(logging.Formatter):
    """Structured JSON logs. CR/LF are escaped by json.dumps, which prevents log
    injection (forging fake log lines through user input)."""

    def format(self, record):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def neutralise(s, limit=200) -> str:
    """Strip control characters from untrusted data before it is stored in logs."""
    return re.sub(r"[\x00-\x1f\x7f]", "?", str(s))[:limit]
