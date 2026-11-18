"""Secure Daily Expense Tracker — Enhanced."""

import csv
import io
import os
import re
import html
import json
from datetime import datetime, date, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, g, jsonify, Response)
from werkzeug.security import generate_password_hash, check_password_hash

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me-7x9k")

DATABASE = os.path.join(os.path.dirname(__file__), "expenses.db")
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
        db = g._database = __import__("sqlite3").connect(DATABASE)
        db.row_factory = __import__("sqlite3").Row
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
            CREATE TABLE IF NOT EXISTS expenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                category    TEXT    NOT NULL,
                amount      REAL    NOT NULL,
                date        TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS failed_logins (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL,
                ip_address   TEXT,
                attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        db.commit()

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
def validate_amount(raw):
    try:
        v = float(raw)
        if v <= 0:
            return None, "Amount must be greater than zero."
        return round(v, 2), None
    except (ValueError, TypeError):
        return None, "Amount must be a valid number."

def validate_date(raw):
    try:
        datetime.strptime(raw, "%Y-%m-%d")
        return raw, None
    except ValueError:
        return None, "Date must be YYYY-MM-DD."

def validate_category(raw):
    if raw not in ALLOWED_CATEGORIES:
        return None, f"Invalid category."
    return raw, None

def sanitize(raw):
    # Strip and limit only — Jinja2 auto-escapes at render time (XSS prevention)
    # html.escape here would double-encode and display entities as literal text
    return (raw or "").strip()[:500]

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
        if not (3 <= len(username) <= 50) or not re.fullmatch(r"[a-zA-Z0-9_]+", username):
            flash("Username: 3–50 chars, letters/numbers/underscore only.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")
        db = get_db()
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already taken.", "error")
            return render_template("register.html")
        db.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                   (username, generate_password_hash(password)))
        db.commit()
        flash("Account created! Sign in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db       = get_db()
        user     = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            db.execute("INSERT INTO failed_logins (username, ip_address) VALUES (?,?)",
                       (username, request.remote_addr))
            db.commit()
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        session.clear()
        session["user_id"]  = user["id"]
        session["username"] = user["username"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
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
    user_id = session["user_id"]
    cat, e1  = validate_category(request.form.get("category","").strip())
    amt, e2  = validate_amount(request.form.get("amount","").strip())
    dt,  e3  = validate_date(request.form.get("date","").strip())
    for err in (e1, e2, e3):
        if err: flash(err, "error"); return redirect(url_for("dashboard"))
    desc = sanitize(request.form.get("description",""))
    get_db().execute(
        "INSERT INTO expenses (user_id,category,amount,date,description) VALUES (?,?,?,?,?)",
        (user_id, cat, amt, dt, desc)
    )
    get_db().commit()
    flash("Expense added.", "success")
    return redirect(url_for("dashboard"))

@app.route("/edit_expense/<int:expense_id>", methods=["POST"])
@login_required
def edit_expense(expense_id):
    user_id = session["user_id"]
    db      = get_db()
    # Verify ownership before update
    if not db.execute("SELECT id FROM expenses WHERE id=? AND user_id=?",
                      (expense_id, user_id)).fetchone():
        flash("Not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    cat, e1 = validate_category(request.form.get("category","").strip())
    amt, e2 = validate_amount(request.form.get("amount","").strip())
    dt,  e3 = validate_date(request.form.get("date","").strip())
    for err in (e1, e2, e3):
        if err: flash(err, "error"); return redirect(url_for("dashboard"))
    desc = sanitize(request.form.get("description",""))
    db.execute(
        "UPDATE expenses SET category=?,amount=?,date=?,description=? WHERE id=? AND user_id=?",
        (cat, amt, dt, desc, expense_id, user_id)
    )
    db.commit()
    flash("Expense updated.", "success")
    return redirect(url_for("dashboard"))

@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
@login_required
def delete_expense(expense_id):
    user_id = session["user_id"]
    db      = get_db()
    if not db.execute("SELECT id FROM expenses WHERE id=? AND user_id=?",
                      (expense_id, user_id)).fetchone():
        flash("Not found or access denied.", "error")
        return redirect(url_for("dashboard"))
    db.execute("DELETE FROM expenses WHERE id=? AND user_id=?", (expense_id, user_id))
    db.commit()
    flash("Expense deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/export_csv")
@login_required
def export_csv():
    user_id = session["user_id"]
    rows    = get_db().execute(
        "SELECT date, category, amount, description FROM expenses WHERE user_id=? ORDER BY date DESC",
        (user_id,)
    ).fetchall()
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["Date", "Category", "Amount", "Description"])
    for r in rows:
        w.writerow([r["date"], r["category"], r["amount"], r["description"]])
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

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"✅  DB ready · http://127.0.0.1:{port}")
    app.run(debug=True, port=port)
