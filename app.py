"""Secure Daily Expense Tracker.

Security controls are tagged V1-V12 to match the security design document.
"""

import csv
import io
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, date, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g, jsonify, Response)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

# ── App setup ──────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
# V7: no secret in the source. Without SECRET_KEY set, a random key is made at start-up
# (everyone is simply signed out when the app restarts).
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,                       # V10: JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE="Strict",                   # V10: not sent from other sites
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),   # V10: 15 min idle timeout
    MAX_CONTENT_LENGTH=16 * 1024,                       # V9: reject request bodies over 16 KB
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",  # HTTPS-only when hosted
)
if os.environ.get("BEHIND_PROXY") == "1":
    # Hosting puts a proxy in front: trust one hop so the audit log records the visitor's real IP
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

DATABASE = os.environ.get("DATABASE_PATH") or os.path.join(BASE_DIR, "expenses.db")
MIN_PASSWORD_LENGTH = 12
MAX_DESCRIPTION     = 500
MAX_AMOUNT          = Decimal("1000000")
MAX_LOGIN_FAILURES  = 5
LOCKOUT_MINUTES     = 15
SESSION_MAX_HOURS   = 8
# V3: checked against when the username doesn't exist, so both cases take the same time
DUMMY_HASH = generate_password_hash("timing-equaliser-not-a-real-password")

# V6: error details go to logs/app.log, never to the browser. Passwords are never logged.
os.makedirs(os.path.join(BASE_DIR, "logs"), exist_ok=True)
logging.basicConfig(filename=os.path.join(BASE_DIR, "logs", "app.log"), level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("expense_tracker")

ALLOWED_CATEGORIES = ["Food", "Travel", "Education", "Shopping", "Medical", "Other"]
CATEGORY_COLORS = {
    "Food":      "#f97316",
    "Travel":    "#8b5cf6",
    "Education": "#0ea5e9",
    "Shopping":  "#ec4899",
    "Medical":   "#ef4444",
    "Other":     "#6b7280",
}

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(_exc):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            -- V5: the database rejects bad values too (applies when the table is first created)
            CREATE TABLE IF NOT EXISTS expenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                category    TEXT    NOT NULL CHECK (category IN
                                ('Food','Travel','Education','Shopping','Medical','Other')),
                amount      REAL    NOT NULL CHECK (amount > 0 AND amount <= 1000000),
                date        TEXT    NOT NULL,
                description TEXT    DEFAULT '' CHECK (length(description) <= 500),
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            -- V3: recent failures per username, used for the lockout
            CREATE TABLE IF NOT EXISTS failed_logins (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL,
                ip_address   TEXT,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            -- V8: audit trail; the triggers make it append-only
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                username   TEXT,
                action     TEXT NOT NULL,
                target_id  INTEGER,
                outcome    TEXT NOT NULL,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
        """)
        db.commit()

def audit(action, outcome="OK", target_id=None, user_id=None, username=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, username, action, target_id, outcome, ip_address) "
        "VALUES (?,?,?,?,?,?)",
        (user_id or session.get("user_id"), username or session.get("username"),
         action, target_id, outcome, request.remote_addr),
    )
    db.commit()

# ── Request-wide protections ───────────────────────────────────────────────────
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def security_checks():
    session.permanent = True
    # V10: absolute timeout, even for a session that stays active
    login_at = session.get("login_at")
    if login_at and time.time() - login_at > SESSION_MAX_HOURS * 3600:
        session.clear()
        flash("Your session expired. Please sign in again.", "info")
        return redirect(url_for("login"))
    # CSRF: every form post must carry the secret token from this user's session
    if request.method == "POST":
        expected = session.get("csrf_token")
        sent = request.form.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            log.warning("CSRF check failed path=%s ip=%s", request.path, request.remote_addr)
            flash("Your form expired. Please try again.", "warning")
            return redirect(request.path if request.endpoint in ("login", "register")
                            else url_for("dashboard"))

@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp

@app.errorhandler(Exception)
def handle_error(e):
    if isinstance(e, HTTPException):
        return e
    # V6: the user sees only a reference id; the details stay in the log
    ref = uuid.uuid4().hex[:8]
    log.exception("Unhandled error ref=%s path=%s", ref, request.path)
    return Response(f"Something went wrong. Reference: {ref}", status=500, mimetype="text/plain")

# ── Auth decorator ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Validators ─────────────────────────────────────────────────────────────────
# V5: allow-list validation. Invalid input is rejected, never silently "fixed".
def validate_amount(raw):
    try:
        v = Decimal((raw or "").strip())        # Decimal, not float: exact money values
    except InvalidOperation:
        return None, "Amount must be a valid number."
    if not v.is_finite() or v <= 0:            # rejects NaN, Infinity, zero and negatives
        return None, "Amount must be greater than zero."
    if v > MAX_AMOUNT:
        return None, "Amount must be at most $1,000,000."
    if v.as_tuple().exponent < -2:
        return None, "Amount can have at most 2 decimal places."
    return float(v), None

def validate_date(raw):
    try:
        d = datetime.strptime(raw or "", "%Y-%m-%d").date()
    except ValueError:
        return None, "Date must be YYYY-MM-DD."
    if d > date.today():
        return None, "Date can't be in the future."
    if d.year < 2000:
        return None, "Date is too far in the past."
    return d.isoformat(), None

def validate_category(raw):
    if raw not in ALLOWED_CATEGORIES:
        return None, "Invalid category."
    return raw, None

def validate_description(raw):
    # Not HTML-escaped here: Jinja2 escapes at display time, so escaping now would double-encode.
    text = (raw or "").strip()
    if len(text) > MAX_DESCRIPTION:
        return None, f"Description must be {MAX_DESCRIPTION} characters or fewer."
    if any(ord(c) < 32 and c not in "\n\t" for c in text):
        return None, "Description contains invalid characters."
    return text, None

def read_expense_form():
    """Validate the add/edit form. Returns (values, first_error)."""
    f = request.form
    cat,  e1 = validate_category(f.get("category", "").strip())
    amt,  e2 = validate_amount(f.get("amount", ""))
    dt,   e3 = validate_date(f.get("date", "").strip())
    desc, e4 = validate_description(f.get("description", ""))
    error = next((e for e in (e1, e2, e3, e4) if e), None)
    return (cat, amt, dt, desc), error

# ── Helpers ────────────────────────────────────────────────────────────────────
def _month_bounds(yr, mo):
    import calendar
    first = date(yr, mo, 1)
    last  = date(yr, mo, calendar.monthrange(yr, mo)[1])
    return first.isoformat(), last.isoformat()

def _stats(db, user_id):
    """Compute summary stats for the dashboard."""
    today = date.today()
    cur_start, cur_end = _month_bounds(today.year, today.month)

    if today.month == 1:
        prev_yr, prev_mo = today.year - 1, 12
    else:
        prev_yr, prev_mo = today.year, today.month - 1
    prev_start, prev_end = _month_bounds(prev_yr, prev_mo)

    def scalar(q, *p):
        return db.execute(q, p).fetchone()[0] or 0

    this_month  = scalar("SELECT SUM(amount) FROM expenses WHERE user_id=? AND date BETWEEN ? AND ?",
                         user_id, cur_start, cur_end)
    last_month  = scalar("SELECT SUM(amount) FROM expenses WHERE user_id=? AND date BETWEEN ? AND ?",
                         user_id, prev_start, prev_end)
    all_time    = scalar("SELECT SUM(amount) FROM expenses WHERE user_id=?", user_id)
    count       = scalar("SELECT COUNT(*) FROM expenses WHERE user_id=?", user_id)

    biggest_row = db.execute(
        "SELECT amount, category, description FROM expenses WHERE user_id=? ORDER BY amount DESC LIMIT 1",
        (user_id,)
    ).fetchone()

    top_cat_row = db.execute(
        "SELECT category, SUM(amount) t FROM expenses WHERE user_id=? AND date BETWEEN ? AND ? "
        "GROUP BY category ORDER BY t DESC LIMIT 1",
        (user_id, cur_start, cur_end)
    ).fetchone()

    pct_change = None
    if last_month > 0:
        pct_change = round((this_month - last_month) / last_month * 100, 1)

    return {
        "this_month":  this_month,
        "last_month":  last_month,
        "pct_change":  pct_change,
        "all_time":    all_time,
        "count":       count,
        "biggest":     dict(biggest_row) if biggest_row else None,
        "top_cat":     dict(top_cat_row) if top_cat_row else None,
    }

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        if not username or not (3 <= len(username) <= 50) or not re.fullmatch(r"[a-zA-Z0-9_]+", username):
            flash("Username: 3–50 chars, letters/numbers/underscore only.", "error")
            return render_template("register.html")
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.", "error")
            return render_template("register.html")
        if len(password) > 128:
            flash("Password must be 128 characters or fewer.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already taken.", "error")
            return render_template("register.html")
        # V2: salted, slow hash (Werkzeug uses scrypt); the plain password is never stored
        cur = db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                         (username, generate_password_hash(password)))
        db.commit()
        audit("REGISTER", target_id=cur.lastrowid, user_id=cur.lastrowid, username=username)
        flash("Account created! Sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:50]
        password = request.form.get("password", "")
        db       = get_db()
        # V3: one message for every failure, so attackers can't tell which usernames exist
        generic  = "Invalid username or password, or the account is temporarily locked."

        if is_locked(db, username):
            audit("LOGIN_BLOCKED", "DENIED", username=username)
            flash(generic, "error")
            return render_template("login.html")

        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        password_ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
        if not user or not password_ok:
            db.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?,?)",
                       (username, request.remote_addr))
            db.commit()
            audit("LOGIN_FAILED", "DENIED", username=username)
            flash(generic, "error")
            return render_template("login.html")

        db.execute("DELETE FROM failed_logins WHERE username=?", (username,))
        db.commit()
        # V10: a brand-new session on login (prevents session fixation)
        session.clear()
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        session["login_at"] = time.time()
        audit("LOGIN")
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

def is_locked(db, username):
    recent = db.execute(
        "SELECT COUNT(*) FROM failed_logins WHERE username=? AND attempted_at >= datetime('now', ?)",
        (username, f"-{LOCKOUT_MINUTES} minutes"),
    ).fetchone()[0]
    return recent >= MAX_LOGIN_FAILURES

@app.route("/logout")
@login_required
def logout():
    audit("LOGOUT")
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db      = get_db()
    user_id = session["user_id"]

    cat_filter = request.args.get("category", "")
    date_from  = request.args.get("date_from", "")
    date_to    = request.args.get("date_to", "")
    sort_by    = request.args.get("sort", "date")
    sort_dir   = request.args.get("dir", "desc")

    allowed_sorts = {"date", "amount", "category"}
    if sort_by not in allowed_sorts:
        sort_by = "date"
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    q      = "SELECT * FROM expenses WHERE user_id=?"
    params = [user_id]
    if cat_filter and cat_filter in ALLOWED_CATEGORIES:
        q += " AND category=?"; params.append(cat_filter)
    if date_from:
        try: datetime.strptime(date_from, "%Y-%m-%d"); q += " AND date>=?"; params.append(date_from)
        except ValueError: pass
    if date_to:
        try: datetime.strptime(date_to, "%Y-%m-%d"); q += " AND date<=?"; params.append(date_to)
        except ValueError: pass

    q += f" ORDER BY {sort_by} {sort_dir}, created_at DESC"
    expenses = db.execute(q, params).fetchall()
    total    = sum(e["amount"] for e in expenses)

    # Category counts for sidebar
    cat_counts = {c: 0 for c in ALLOWED_CATEGORIES}
    for row in db.execute("SELECT category, COUNT(*) n FROM expenses WHERE user_id=? GROUP BY category", (user_id,)):
        cat_counts[row["category"]] = row["n"]

    stats = _stats(db, user_id)

    return render_template("dashboard.html",
        expenses=expenses, total=total,
        categories=ALLOWED_CATEGORIES, cat_colors=CATEGORY_COLORS,
        cat_filter=cat_filter, date_from=date_from, date_to=date_to,
        sort_by=sort_by, sort_dir=sort_dir,
        cat_counts=cat_counts, stats=stats,
        today=date.today().isoformat(),
    )

@app.route("/add_expense", methods=["POST"])
@login_required
def add_expense():
    (cat, amt, dt, desc), error = read_expense_form()
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard"))
    db  = get_db()
    # V1: values are bound with ? placeholders, never pasted into the SQL text
    cur = db.execute(
        "INSERT INTO expenses (user_id,category,amount,date,description) VALUES (?,?,?,?,?)",
        (session["user_id"], cat, amt, dt, desc)
    )
    db.commit()
    audit("ADD_EXPENSE", target_id=cur.lastrowid)
    flash("Expense added.", "success")
    return redirect(url_for("dashboard"))

@app.route("/edit_expense/<int:expense_id>", methods=["POST"])
@login_required
def edit_expense(expense_id):
    (cat, amt, dt, desc), error = read_expense_form()
    if error:
        flash(error, "error")
        return redirect(url_for("dashboard"))
    db  = get_db()
    # V4: the user_id condition means another user's expense is simply "not found"
    cur = db.execute(
        "UPDATE expenses SET category=?,amount=?,date=?,description=? WHERE id=? AND user_id=?",
        (cat, amt, dt, desc, expense_id, session["user_id"])
    )
    db.commit()
    if cur.rowcount == 0:
        audit("EDIT_EXPENSE", "DENIED", target_id=expense_id)
        flash("Expense not found.", "error")
        return redirect(url_for("dashboard"))
    audit("EDIT_EXPENSE", target_id=expense_id)
    flash("Expense updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
@login_required
def delete_expense(expense_id):
    db  = get_db()
    # V4: same reply for "doesn't exist" and "belongs to someone else"
    cur = db.execute("DELETE FROM expenses WHERE id=? AND user_id=?",
                     (expense_id, session["user_id"]))
    db.commit()
    if cur.rowcount == 0:
        audit("DELETE_EXPENSE", "DENIED", target_id=expense_id)
        flash("Expense not found.", "error")
        return redirect(url_for("dashboard"))
    audit("DELETE_EXPENSE", target_id=expense_id)
    flash("Expense deleted.", "success")
    return redirect(url_for("dashboard"))

def csv_safe(value):
    # V11: a cell starting with = + - @ would run as a formula in Excel; prefix it with '
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

@app.route("/export_csv")
@login_required
def export_csv():
    rows = get_db().execute(
        "SELECT date, category, amount, description FROM expenses WHERE user_id=? ORDER BY date DESC",
        (session["user_id"],)
    ).fetchall()
    buf = io.StringIO()
    w   = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["Date", "Category", "Amount", "Description"])
    for r in rows:
        w.writerow([csv_safe(r["date"]), csv_safe(r["category"]),
                    f"{r['amount']:.2f}", csv_safe(r["description"])])
    audit("EXPORT_CSV", target_id=len(rows))
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=expenses_{date.today()}.csv"}
    )

@app.route("/api/chart_data")
@login_required
def chart_data():
    user_id = session["user_id"]
    db      = get_db()

    # By category — all time
    by_cat = {}
    for r in db.execute("SELECT category, SUM(amount) t FROM expenses WHERE user_id=? GROUP BY category",
                        (user_id,)):
        by_cat[r["category"]] = round(r["t"], 2)

    # By month — last 7 months
    by_month = []
    for r in db.execute(
        "SELECT strftime('%Y-%m', date) mo, SUM(amount) t FROM expenses "
        "WHERE user_id=? AND date >= date('now','-7 months') GROUP BY mo ORDER BY mo",
        (user_id,)
    ):
        by_month.append({"month": r["mo"], "total": round(r["t"], 2)})

    return jsonify({"by_category": by_cat, "by_month": by_month,
                    "colors": CATEGORY_COLORS})

init_db()   # runs on import too, so a production server (gunicorn) gets the tables

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"DB ready · http://127.0.0.1:{port}")
    # V6: the debugger shows code and allows running commands, so it's off unless FLASK_DEBUG=1
    app.run(host="127.0.0.1", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
