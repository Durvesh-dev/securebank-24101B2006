"""Configuration management.

Every secret comes from the environment. Nothing sensitive is hard-coded or
committed. In development (no env vars set) random keys are generated per
process so the app still runs, with a loud warning.
"""
import hashlib
import logging
import os
import secrets

log = logging.getLogger("securebank.config")


def _env_key(name: str) -> bytes:
    """Return a 256-bit key for one purpose. The env value (any high-entropy
    string, e.g. Render's generated value) is run through SHA-256 with the key
    name as context, so each purpose gets an independent key."""
    raw = os.environ.get(name)
    if raw:
        if len(raw) < 32:
            raise RuntimeError(f"{name} is too short - use at least 32 random characters")
    else:
        if os.environ.get("APP_ENV") == "production":
            raise RuntimeError(f"{name} must be set in production")   # fail closed
        path = os.path.join(os.path.dirname(__file__), ".dev-secrets")
        os.makedirs(path, mode=0o700, exist_ok=True)
        f = os.path.join(path, name)
        if not os.path.exists(f):
            with open(os.open(f, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fh:
                fh.write(secrets.token_urlsafe(48))
        raw = open(f).read().strip()
        log.warning("%s not set - using local development key in .dev-secrets/", name)
    return hashlib.sha256(f"{name}:{raw}".encode()).digest()


class Config:
    ENV = os.environ.get("APP_ENV", "development")
    PRODUCTION = ENV == "production"

    # Never run the debugger in production: it allows remote code execution.
    DEBUG = False
    TESTING = False

    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "securebank.db"))

    # Separate keys for separate purposes (key separation principle).
    DATA_KEY = _env_key("DATA_ENCRYPTION_KEY")      # AES-256-GCM for PII at rest
    LEDGER_KEY = _env_key("LEDGER_HMAC_KEY")        # HMAC-SHA256 signing of transactions
    # Flask's signed cookie is used ONLY for one-time flash messages, never for auth.
    SECRET_KEY = _env_key("FLASK_SECRET_KEY")
    SESSION_COOKIE_NAME = "sb_flash"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = PRODUCTION

    # Session management
    SESSION_COOKIE = "__Host-sb_sid" if PRODUCTION else "sb_sid"
    COOKIE_SECURE = PRODUCTION
    SESSION_IDLE_TIMEOUT = 10 * 60          # 10 minutes of inactivity
    SESSION_ABSOLUTE_TIMEOUT = 8 * 60 * 60  # 8 hours max lifetime
    MFA_PENDING_TIMEOUT = 5 * 60

    # Authentication policy
    MAX_FAILED_LOGINS = 5
    LOCKOUT_SECONDS = 15 * 60
    LOGIN_RATE_PER_MIN = 10                 # per client IP

    # Business limits (parameter manipulation defence)
    MAX_TRANSFER_PAISE = 1_00_000 * 100     # Rs 1,00,000 per transaction
    DAILY_LIMIT_PAISE = 2_00_000 * 100      # Rs 2,00,000 per day
    PENDING_TRANSFER_TTL = 5 * 60

    MAX_CONTENT_LENGTH = 16 * 1024          # reject oversized request bodies
    DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"
