"""SecureBank - a deliberately security-hardened online banking web application.

Layered architecture:  browser -> Flask routes (presentation) -> service checks
(authz, validation, business rules) -> parameterised SQLite data layer.
"""
import collections
import logging
import secrets
import sys
import time
from functools import wraps

from flask import (Flask, abort, flash, g, make_response, redirect, render_template,
                   request, url_for)
from itsdangerous import BadData, URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

import db as dbm
from config import Config
from security import (DUMMY_HASH, SafeJsonFormatter, ValidationError, Vault, clean,
                      hash_password, mask_account, neutralise, new_totp_secret,
                      parse_amount, password_problems, rupees, sha256, sign,
                      totp_now, verify_password, verify_totp)

# ------------------------------------------------------------------ logging
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(SafeJsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])
log = logging.getLogger("securebank")

app = Flask(__name__)
app.config.from_object(Config)
vault = Vault(Config.DATA_KEY)
if Config.PRODUCTION:
    # Trust exactly one reverse proxy hop (Render/Railway load balancer).
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.teardown_appcontext(dbm.close_db)
dbm.init_db(app, vault)
app.jinja_env.globals.update(rupees=rupees, mask=mask_account)
app.jinja_env.filters["datefmt"] = lambda ts: time.strftime("%d %b %Y, %H:%M", time.gmtime(int(ts) + 19800))  # IST

# Anonymous forms (sign in / sign up) get a signed, time-limited token that needs
# no cookie, so a cached or re-opened page never fails. Combined with the Origin /
# Referer check below, a cross-site page still cannot forge the request.
_anon_csrf = URLSafeTimedSerializer(Config.SECRET_KEY, salt="anon-csrf")
ANON_FORM_ENDPOINTS = {"login", "register"}
ANON_TOKEN_MAX_AGE = 2 * 60 * 60


# ------------------------------------------------------------------ audit log
def audit(event, outcome="success", detail="", user=None):
    """Append-only, hash-chained audit trail: each row stores the hash of the
    previous row, so deleting or editing history breaks the chain (tamper-evident)."""
    db = dbm.get_db()
    user = user or g.get("user")
    prev = db.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["row_hash"] if prev else "GENESIS"
    ts = int(time.time())
    uid = user["id"] if user else None
    uname = user["username"] if user else None
    ip = request.remote_addr if request else None
    detail = neutralise(detail)
    row_hash = sign(Config.LEDGER_KEY, prev_hash, ts, uid, uname, event, outcome, ip, detail)
    db.execute("INSERT INTO audit_log (ts,user_id,username,event,outcome,ip,detail,prev_hash,row_hash) "
               "VALUES (?,?,?,?,?,?,?,?,?)", (ts, uid, uname, event, outcome, ip, detail, prev_hash, row_hash))
    log.info("audit event=%s outcome=%s user=%s ip=%s", event, outcome, uname, ip)


# ------------------------------------------------------------------ rate limiting
_hits = collections.defaultdict(collections.deque)


def rate_limited(key, limit, window=60):
    now = time.time()
    q = _hits[key]
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


# ------------------------------------------------------------------ sessions
def _set_cookie(resp, name, value, max_age=None):
    resp.set_cookie(name, value, max_age=max_age, httponly=True, secure=Config.COOKIE_SECURE,
                    samesite="Strict", path="/")


def start_session(user, stage, resp):
    """Issue a brand-new random token on every privilege change (login, MFA)
    which defeats session fixation. Only a SHA-256 of the token is stored."""
    old = request.cookies.get(Config.SESSION_COOKIE)
    db = dbm.get_db()
    if old:
        db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (sha256(old),))
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute("INSERT INTO sessions (token_hash,user_id,stage,csrf,created_at,last_seen,ip,user_agent) "
               "VALUES (?,?,?,?,?,?,?,?)",
               (sha256(token), user["id"], stage, secrets.token_urlsafe(24), now, now,
                request.remote_addr, neutralise(request.user_agent.string, 120)))
    _set_cookie(resp, Config.SESSION_COOKIE, token)
    return resp


@app.before_request
def load_session():
    g.user = g.sess = None
    token = request.cookies.get(Config.SESSION_COOKIE)
    if not token:
        return
    db = dbm.get_db()
    s = db.execute("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (sha256(token),)).fetchone()
    if not s:
        return
    now = int(time.time())
    idle = Config.MFA_PENDING_TIMEOUT if s["stage"] == "mfa" else Config.SESSION_IDLE_TIMEOUT
    if now - s["last_seen"] > idle or now - s["created_at"] > Config.SESSION_ABSOLUTE_TIMEOUT:
        db.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (s["token_hash"],))
        g.expired = True
        return
    db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, s["token_hash"]))
    g.sess = s
    g.user = db.execute("SELECT * FROM users WHERE id=?", (s["user_id"],)).fetchone()


# ------------------------------------------------------------------ CSRF
def csrf_token():
    if g.get("sess"):
        return g.sess["csrf"]                       # synchronizer token bound to the session
    if "anon_csrf" not in g:
        g.anon_csrf = _anon_csrf.dumps(secrets.token_hex(8))
    return g.anon_csrf


app.jinja_env.globals["csrf_token"] = csrf_token


def _same_origin(url):
    return url.rstrip("/").startswith(request.host_url.rstrip("/"))


@app.before_request
def csrf_protect():
    if request.method != "POST":
        return
    # 1) Origin check - reject cross-site form posts outright (Referer as fallback).
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    if (origin and origin != "null" and not _same_origin(origin)) or (not origin and referer and not _same_origin(referer)):
        audit("csrf_blocked", "denied", f"origin={origin or referer}")
        abort(403)
    # 2) Token check.
    sent = request.form.get("csrf_token", "")
    if g.get("sess") and sent and secrets.compare_digest(sent, g.sess["csrf"]):
        return
    if request.endpoint in ANON_FORM_ENDPOINTS:
        try:
            _anon_csrf.loads(sent, max_age=ANON_TOKEN_MAX_AGE)
            return
        except BadData:
            pass
    audit("csrf_blocked", "denied", "token missing or invalid")
    if request.endpoint in ANON_FORM_ENDPOINTS:
        flash("That form had expired. Please try again.", "warn")
        return redirect(url_for(request.endpoint))
    abort(403)


# ------------------------------------------------------------------ security headers
@app.after_request
def harden(resp):
    h = resp.headers
    h["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                    "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                                    "form-action 'self'; frame-ancestors 'none'")
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if Config.PRODUCTION:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if g.get("user") or resp.mimetype == "text/html":
        h["Cache-Control"] = "no-store"   # no stale forms / banking pages from cache  # banking pages must not sit in shared caches
    h["Server"] = "SecureBank"           # hide framework/version banner
    return resp


# ------------------------------------------------------------------ authorization
def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if not g.user or g.sess["stage"] != "full":
            if g.get("expired"):
                flash("Your session expired. Please sign in again.", "warn")
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper


def role_required(role):
    def deco(view):
        @wraps(view)
        @login_required
        def wrapper(*a, **kw):
            if g.user["role"] != role:  # role read from DB, never from the request
                audit("authz_denied", "denied", f"path={request.path}")
                abort(403)
            return view(*a, **kw)
        return wrapper
    return deco


def owned_account(public_id):
    """Object-level authorization (prevents IDOR). Returns 404 rather than 403
    so attackers cannot learn which account ids exist."""
    try:
        public_id = clean("public_id", public_id)
    except ValidationError:
        abort(404)
    acct = dbm.get_db().execute("SELECT * FROM accounts WHERE public_id=? AND user_id=?",
                                (public_id, g.user["id"])).fetchone()
    if not acct:
        audit("idor_attempt", "denied", f"account={public_id}")
        abort(404)
    return acct


# ------------------------------------------------------------------ public routes
@app.get("/")
def index():
    return redirect(url_for("dashboard" if g.user and g.sess["stage"] == "full" else "login"))


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/controls")
def controls():
    return render_template("controls.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        try:
            username = clean("username", f.get("username"))
            full_name = clean("full_name", f.get("full_name"))
            email = clean("email", f.get("email"))
            phone = clean("phone", f.get("phone"))
            password = f.get("password", "")
            if password != f.get("confirm", ""):
                raise ValidationError("Passwords do not match.")
            problems = password_problems(password, username)
            if problems:
                raise ValidationError("Password must have " + ", ".join(problems) + ".")
        except ValidationError as e:
            flash(str(e), "error")
            return render_template("register.html", form=f), 400
        db = dbm.get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("That username is not available.", "error")
            return render_template("register.html", form=f), 400
        db.execute("BEGIN IMMEDIATE")
        cur = db.execute(
            "INSERT INTO users (username,pw_hash,role,full_name,email_enc,phone_enc,created_at) "
            "VALUES (?,?,'customer',?,?,?,?)",   # role is fixed server-side: no mass assignment
            (username, hash_password(password), full_name, vault.encrypt(email), vault.encrypt(phone), int(time.time())))
        acct = dbm.new_account_number(db)
        opening = 10_000_00 if Config.DEMO_MODE else 0
        db.execute("INSERT INTO accounts (public_id,user_id,acct_no_hash,acct_no_enc,last4,kind,balance_paise) "
                   "VALUES (?,?,?,?,?,?,?)",
                   (dbm.new_public_id(), cur.lastrowid, sha256(acct), vault.encrypt(acct), acct[-4:], "Savings", opening))
        db.execute("COMMIT")
        audit("register", detail=f"new customer {username}", user={"id": cur.lastrowid, "username": username})
        flash("Account opened. Please sign in." + (" Demo balance: ₹10,000." if Config.DEMO_MODE else ""), "ok")
        return redirect(url_for("login"))
    return render_template("register.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if rate_limited(f"login:{request.remote_addr}", Config.LOGIN_RATE_PER_MIN):
            audit("login_rate_limited", "denied")
            abort(429)
        db = dbm.get_db()
        raw_user = (request.form.get("username") or "").strip().lower()[:40]
        password = request.form.get("password", "")[:128]
        user = db.execute("SELECT * FROM users WHERE username=?", (raw_user,)).fetchone()
        now = int(time.time())
        generic = "Invalid username or password."   # same message for every failure
        if not user:
            verify_password(password, DUMMY_HASH)      # equalise timing
            audit("login", "failure", f"unknown user {raw_user}")
            flash(generic, "error")
            return render_template("login.html"), 401
        if user["locked_until"] > now:
            audit("login", "locked", user=user)
            flash("Account temporarily locked after repeated failures. Try again later.", "error")
            return render_template("login.html"), 423
        if not verify_password(password, user["pw_hash"]):
            fails = user["failed_attempts"] + 1
            locked = now + Config.LOCKOUT_SECONDS if fails >= Config.MAX_FAILED_LOGINS else 0
            db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                       (0 if locked else fails, locked, user["id"]))
            audit("login", "failure", f"bad password attempt {fails}", user=user)
            if locked:
                audit("account_locked", "denied", user=user)
            flash(generic, "error")
            return render_template("login.html"), 401
        db.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (user["id"],))
        if user["totp_enabled"]:
            audit("login_password_ok", "mfa_pending", user=user)
            return start_session(user, "mfa", redirect(url_for("login_mfa")))
        audit("login", user=user)
        return start_session(user, "full", redirect(url_for("dashboard")))
    return render_template("login.html")


@app.route("/login/mfa", methods=["GET", "POST"])
def login_mfa():
    if not g.user or g.sess["stage"] != "mfa":
        return redirect(url_for("login"))
    if request.method == "POST":
        if rate_limited(f"mfa:{g.user['id']}", 5):
            abort(429)
        secret = vault.decrypt(g.user["totp_secret_enc"])
        counter = verify_totp(secret, request.form.get("code", ""), g.user["totp_last_counter"])
        if counter is None:
            audit("mfa", "failure")
            flash("Invalid or already-used code.", "error")
            return render_template("mfa.html"), 401
        dbm.get_db().execute("UPDATE users SET totp_last_counter=? WHERE id=?", (counter, g.user["id"]))
        audit("login", detail="password + TOTP")
        return start_session(g.user, "full", redirect(url_for("dashboard")))
    return render_template("mfa.html")


@app.post("/logout")
def logout():
    if g.sess:
        dbm.get_db().execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (g.sess["token_hash"],))
        audit("logout")
    resp = redirect(url_for("login"))
    resp.delete_cookie(Config.SESSION_COOKIE, path="/")
    flash("You have been signed out.", "ok")
    return resp


# ------------------------------------------------------------------ customer routes
@app.get("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin"))
    db = dbm.get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", (g.user["id"],)).fetchall()
    ids = [a["id"] for a in accounts] or [0]
    marks = ",".join("?" * len(ids))
    txns = db.execute(
        f"SELECT t.*, fa.last4 AS from_last4, ta.last4 AS to_last4, fa.user_id AS from_user "
        f"FROM transactions t LEFT JOIN accounts fa ON fa.id=t.from_account JOIN accounts ta ON ta.id=t.to_account "
        f"WHERE t.from_account IN ({marks}) OR t.to_account IN ({marks}) ORDER BY t.id DESC LIMIT 10",
        ids + ids).fetchall()
    return render_template("dashboard.html", accounts=accounts, txns=txns)


@app.get("/accounts/<public_id>")
@login_required
def account_detail(public_id):
    acct = owned_account(public_id)
    db = dbm.get_db()
    txns = db.execute(
        "SELECT t.*, fa.last4 AS from_last4, ta.last4 AS to_last4 FROM transactions t "
        "LEFT JOIN accounts fa ON fa.id=t.from_account JOIN accounts ta ON ta.id=t.to_account "
        "WHERE t.from_account=? OR t.to_account=? ORDER BY t.id DESC LIMIT 50", (acct["id"], acct["id"])).fetchall()
    full_no = vault.decrypt(acct["acct_no_enc"])
    audit("view_account_number", detail=f"account ...{acct['last4']}")
    return render_template("account.html", acct=acct, txns=txns, full_no=full_no)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    db = dbm.get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id=?", (g.user["id"],)).fetchall()
    if g.user["role"] != "customer":
        abort(403)
    if request.method == "POST":
        f = request.form
        try:
            src = owned_account(f.get("from_account"))          # never trust the client's choice
            to_no = clean("account_no", f.get("to_account_no", "").replace(" ", ""))
            amount = parse_amount(f.get("amount"), Config.MAX_TRANSFER_PAISE)
            note = clean("note", f.get("note"), required=False)
            dest = db.execute("SELECT a.*, u.full_name FROM accounts a JOIN users u ON u.id=a.user_id "
                              "WHERE acct_no_hash=?", (sha256(to_no),)).fetchone()
            if not dest:
                raise ValidationError("Beneficiary account not found.")
            if dest["id"] == src["id"]:
                raise ValidationError("You cannot transfer to the same account.")
            if amount > src["balance_paise"]:
                raise ValidationError("Insufficient balance.")
            today = int(time.time()) - int(time.time()) % 86400
            spent = db.execute("SELECT COALESCE(SUM(amount_paise),0) FROM transactions "
                               "WHERE from_account=? AND created_at>=?", (src["id"], today)).fetchone()[0]
            if spent + amount > Config.DAILY_LIMIT_PAISE:
                raise ValidationError(f"Daily limit of {rupees(Config.DAILY_LIMIT_PAISE)} would be exceeded.")
        except ValidationError as e:
            audit("transfer_rejected", "failure", str(e))
            flash(str(e), "error")
            return render_template("transfer.html", accounts=accounts, form=f), 400
        # Store the validated transfer server-side; the confirm step only sends a
        # single-use nonce, so amount/recipient cannot be tampered with in between.
        nonce = secrets.token_urlsafe(24)
        db.execute("DELETE FROM pending_transfers WHERE expires_at<?", (int(time.time()),))
        db.execute("INSERT INTO pending_transfers VALUES (?,?,?,?,?,?,?)",
                   (nonce, g.sess["token_hash"], src["id"], dest["id"], amount, note,
                    int(time.time()) + Config.PENDING_TRANSFER_TTL))
        name = dest["full_name"]
        masked_name = name.split()[0] + " " + "".join(p[0] + "." for p in name.split()[1:])
        return render_template("confirm.html", nonce=nonce, src=src, dest=dest, amount=amount,
                               note=note, payee=masked_name, need_otp=bool(g.user["totp_enabled"]))
    return render_template("transfer.html", accounts=accounts, form={})


@app.post("/transfer/confirm")
@login_required
def transfer_confirm():
    db = dbm.get_db()
    nonce = request.form.get("nonce", "")
    p = db.execute("SELECT * FROM pending_transfers WHERE nonce=? AND session_hash=?",
                   (nonce, g.sess["token_hash"])).fetchone()
    db.execute("DELETE FROM pending_transfers WHERE nonce=?", (nonce,))   # single use
    if not p or p["expires_at"] < time.time():
        audit("transfer_confirm", "failure", "invalid or expired nonce")
        flash("This transfer request expired or is invalid. Please start again.", "error")
        return redirect(url_for("transfer"))
    if g.user["totp_enabled"]:   # step-up authentication for a high-risk action
        counter = verify_totp(vault.decrypt(g.user["totp_secret_enc"]), request.form.get("code", ""),
                              g.user["totp_last_counter"])
        if counter is None:
            audit("transfer_confirm", "failure", "bad step-up OTP")
            flash("Invalid authenticator code. Transfer cancelled.", "error")
            return redirect(url_for("transfer"))
        db.execute("UPDATE users SET totp_last_counter=? WHERE id=?", (counter, g.user["id"]))
    db.execute("BEGIN IMMEDIATE")   # atomic: debit, credit and ledger entry succeed or fail together
    debited = db.execute("UPDATE accounts SET balance_paise=balance_paise-? WHERE id=? AND user_id=? "
                         "AND balance_paise>=?", (p["amount_paise"], p["from_account"], g.user["id"],
                                                  p["amount_paise"])).rowcount
    if not debited:
        db.execute("ROLLBACK")
        flash("Insufficient balance.", "error")
        return redirect(url_for("transfer"))
    db.execute("UPDATE accounts SET balance_paise=balance_paise+? WHERE id=?", (p["amount_paise"], p["to_account"]))
    tid, ts = dbm.new_public_id(), int(time.time())
    db.execute("INSERT INTO transactions (public_id,from_account,to_account,amount_paise,note,created_at,signature) "
               "VALUES (?,?,?,?,?,?,?)", (tid, p["from_account"], p["to_account"], p["amount_paise"], p["note"], ts,
                                          sign(Config.LEDGER_KEY, tid, p["from_account"], p["to_account"],
                                               p["amount_paise"], p["note"], ts)))
    db.execute("COMMIT")
    audit("transfer", detail=f"{rupees(p['amount_paise'])} ref {tid}")
    flash(f"Transferred {rupees(p['amount_paise'])}. Reference {tid[:12].upper()}.", "ok")
    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------ account security
@app.get("/security")
@login_required
def security_page():
    sessions = dbm.get_db().execute(
        "SELECT * FROM sessions WHERE user_id=? AND revoked=0 AND stage='full' ORDER BY last_seen DESC",
        (g.user["id"],)).fetchall()
    profile = {"email": vault.decrypt(g.user["email_enc"]), "phone": vault.decrypt(g.user["phone_enc"])}
    return render_template("security.html", sessions=sessions, profile=profile)


@app.post("/security/2fa/start")
@login_required
def mfa_start():
    secret = new_totp_secret()
    dbm.get_db().execute("UPDATE users SET totp_secret_enc=?, totp_enabled=0 WHERE id=?",
                         (vault.encrypt(secret), g.user["id"]))
    uri = f"otpauth://totp/SecureBank:{g.user['username']}?secret={secret}&issuer=SecureBank"
    demo_code = totp_now(secret) if Config.DEMO_MODE else None
    return render_template("mfa_setup.html", secret=secret, uri=uri, demo_code=demo_code)


@app.post("/security/2fa/enable")
@login_required
def mfa_enable():
    user = dbm.get_db().execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    if not user["totp_secret_enc"]:
        return redirect(url_for("security_page"))
    counter = verify_totp(vault.decrypt(user["totp_secret_enc"]), request.form.get("code", ""), 0)
    if counter is None:
        flash("Code did not match. Start setup again.", "error")
        return redirect(url_for("security_page"))
    dbm.get_db().execute("UPDATE users SET totp_enabled=1, totp_last_counter=? WHERE id=?", (counter, user["id"]))
    audit("mfa_enabled")
    flash("Two-factor authentication is now on.", "ok")
    return redirect(url_for("security_page"))


@app.post("/security/password")
@login_required
def change_password():
    current, new = request.form.get("current", ""), request.form.get("new", "")
    if not verify_password(current, g.user["pw_hash"]):
        audit("password_change", "failure", "wrong current password")
        flash("Current password is incorrect.", "error")
        return redirect(url_for("security_page"))
    problems = password_problems(new, g.user["username"])
    if problems or new != request.form.get("confirm", ""):
        flash("New password must have " + ", ".join(problems or ["matching confirmation"]) + ".", "error")
        return redirect(url_for("security_page"))
    db = dbm.get_db()
    db.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(new), g.user["id"]))
    # Kill every other session after a credential change.
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash<>?", (g.user["id"], g.sess["token_hash"]))
    audit("password_change")
    flash("Password changed. All other sessions were signed out.", "ok")
    return redirect(url_for("security_page"))


@app.post("/security/sessions/revoke")
@login_required
def revoke_sessions():
    dbm.get_db().execute("UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash<>?",
                         (g.user["id"], g.sess["token_hash"]))
    audit("sessions_revoked")
    flash("Signed out of all other devices.", "ok")
    return redirect(url_for("security_page"))


# ------------------------------------------------------------------ admin
@app.get("/admin")
@role_required("admin")
def admin():
    db = dbm.get_db()
    logs = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    users = db.execute("SELECT id,username,role,full_name,totp_enabled,failed_attempts,locked_until "
                       "FROM users ORDER BY id").fetchall()
    return render_template("admin.html", logs=logs, users=users, now=int(time.time()))


@app.post("/admin/unlock/<int:uid>")
@role_required("admin")
def admin_unlock(uid):
    dbm.get_db().execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (uid,))
    audit("admin_unlock", detail=f"user_id={uid}")
    flash("User unlocked.", "ok")
    return redirect(url_for("admin"))


@app.get("/admin/integrity")
@role_required("admin")
def admin_integrity():
    """Re-compute every HMAC: proves no transaction or audit row was altered."""
    db = dbm.get_db()
    bad_tx = [t["public_id"] for t in db.execute("SELECT * FROM transactions")
              if not secrets.compare_digest(t["signature"], sign(Config.LEDGER_KEY, t["public_id"], t["from_account"],
                                            t["to_account"], t["amount_paise"], t["note"], t["created_at"]))]
    prev, bad_log, n = "GENESIS", [], 0
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        n += 1
        expect = sign(Config.LEDGER_KEY, prev, r["ts"], r["user_id"], r["username"], r["event"], r["outcome"],
                      r["ip"], r["detail"])
        if r["prev_hash"] != prev or not secrets.compare_digest(expect, r["row_hash"]):
            bad_log.append(r["id"])
        prev = r["row_hash"]
    tx_count = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    audit("integrity_check", detail=f"bad_tx={len(bad_tx)} bad_log={len(bad_log)}")
    return render_template("integrity.html", bad_tx=bad_tx, bad_log=bad_log, tx_count=tx_count, log_count=n)


# ------------------------------------------------------------------ exception management
@app.errorhandler(Exception)
def handle_error(e):
    """Fail securely: users see a generic page with an incident id; stack traces
    and internals are written only to the server log."""
    if isinstance(e, HTTPException):
        if e.code is None or e.code < 400:
            return e
        code = e.code
    else:
        code = 500
    incident = secrets.token_hex(4).upper()
    if code >= 500:
        log.error("incident=%s path=%s", incident, neutralise(request.path), exc_info=e)
        try:
            dbm.get_db().execute("ROLLBACK")
        except Exception:
            pass
    messages = {400: "The request could not be processed.", 403: "You are not allowed to do that.",
                404: "Page not found.", 405: "Method not allowed.", 413: "Request too large.",
                429: "Too many attempts. Please wait a minute and try again.",
                423: "Account locked."}
    resp = make_response(render_template("error.html", code=code, incident=incident,
                                         message=messages.get(code, "Something went wrong on our side.")), code)
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
