"""Security checks from the verification plan (V1-V11). Run: python3 test_security.py"""

import os
import sqlite3
import sys
import tempfile
import time

import app as tracker

tracker.DATABASE = os.path.join(tempfile.mkdtemp(), "test.db")
tracker.init_db()

TOKEN = "test-csrf-token"
PASSWORD = "correct-horse-battery"
results = []


@tracker.app.route("/_test_crash")
def _test_crash():
    raise RuntimeError("secret internal detail")


def check(label, ok):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + label)


def post(client, path, **data):
    with client.session_transaction() as s:
        s["csrf_token"] = TOKEN
    return client.post(path, data={"csrf_token": TOKEN, **data})


def new_user(username):
    c = tracker.app.test_client()
    post(c, "/register", username=username, password=PASSWORD, confirm_password=PASSWORD)
    post(c, "/login", username=username, password=PASSWORD)
    return c


def db():
    con = sqlite3.connect(tracker.DATABASE)
    con.row_factory = sqlite3.Row
    return con


def count_expenses():
    return db().execute("SELECT COUNT(*) FROM expenses").fetchone()[0]


def logged_in(client):
    return client.get("/dashboard").status_code == 200


TODAY = time.strftime("%Y-%m-%d")
alice = new_user("alice")
bob = new_user("bob")
check("setup: two users can register and sign in", logged_in(alice) and logged_in(bob))

# V1 SQL injection
anon = tracker.app.test_client()
post(anon, "/login", username="' OR '1'='1", password="' OR '1'='1")
check("V1 login with ' OR '1'='1 does not sign in", not logged_in(anon))
post(alice, "/add_expense", category="Food", amount="12.50", date=TODAY,
     description="Food'; DROP TABLE expenses; --")
row = db().execute("SELECT description FROM expenses WHERE description LIKE '%DROP%'").fetchone()
check("V1 DROP TABLE text is stored as plain text, table still exists", row is not None)
ALICE_ROW = "Food&#39;; DROP TABLE"   # how Alice's description looks once escaped in the page
html = alice.get("/dashboard?category=' OR 1=1 --").get_data(as_text=True)
check("V1 injected category filter is ignored", ALICE_ROW in html)

# V2 password storage
stored = db().execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
check("V2 password stored as a salted hash, not plain text",
      PASSWORD not in stored and stored.startswith(("scrypt:", "pbkdf2:")))

# V3 brute force
new_user("carol")
guesser = tracker.app.test_client()
for _ in range(5):
    post(guesser, "/login", username="carol", password="wrong-password")
post(guesser, "/login", username="carol", password=PASSWORD)
check("V3 after 5 wrong passwords even the right one is blocked", not logged_in(guesser))
r1 = post(tracker.app.test_client(), "/login", username="nobody_here", password="x").get_data(as_text=True)
r2 = post(tracker.app.test_client(), "/login", username="alice", password="wrong").get_data(as_text=True)
check("V3 same message for unknown user and wrong password", r1 == r2)

# V4 access control (IDOR)
alice_id = db().execute("SELECT id FROM expenses WHERE description LIKE '%DROP%'").fetchone()[0]
post(bob, f"/delete_expense/{alice_id}")
post(bob, f"/edit_expense/{alice_id}", category="Other", amount="1", date=TODAY, description="hacked")
row = db().execute("SELECT amount, description FROM expenses WHERE id=?", (alice_id,)).fetchone()
check("V4 Bob cannot delete or edit Alice's expense",
      row is not None and row["amount"] == 12.5 and "hacked" not in row["description"])
check("V4 Alice's expense is not shown to Bob",
      ALICE_ROW not in bob.get("/dashboard").get_data(as_text=True))

# V5 input validation
before = count_expenses()
bad_inputs = [
    dict(category="Food", amount="-5", date=TODAY),
    dict(category="Food", amount="1e308", date=TODAY),
    dict(category="Food", amount="10.999", date=TODAY),
    dict(category="Food", amount="nan", date=TODAY),
    dict(category="Food", amount="abc", date=TODAY),
    dict(category="Hacking", amount="5", date=TODAY),
    dict(category="Food", amount="5", date="2999-01-01"),
    dict(category="Food", amount="5", date="not-a-date"),
    dict(category="Food", amount="5", date=TODAY, description="x" * 5000),
]
for data in bad_inputs:
    post(alice, "/add_expense", **data)
check("V5 bad amounts, categories, dates and long text are all rejected",
      count_expenses() == before)

# V6 error handling
resp = alice.get("/_test_crash")
body = resp.get_data(as_text=True)
check("V6 crash shows a reference id only, no internal details",
      resp.status_code == 500 and "Reference" in body and "secret internal detail" not in body)

# V7 secrets
source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")).read()
check("V7 no hard-coded secret key in the source", "dev-only-change-me" not in source)

# V8 audit trail
actions = {r["action"] for r in db().execute("SELECT action FROM audit_log")}
check("V8 audit log records sign-ins, failures, adds and denied deletes",
      {"LOGIN", "LOGIN_FAILED", "ADD_EXPENSE", "DELETE_EXPENSE"} <= actions)
con = db()
try:
    con.execute("DELETE FROM audit_log")
    con.commit()
    check("V8 audit log cannot be deleted", False)
except sqlite3.DatabaseError:
    check("V8 audit log cannot be deleted", True)
finally:
    con.rollback()
    con.close()

# V9 resource limits
resp = post(alice, "/add_expense", category="Food", amount="5", date=TODAY, description="x" * 50_000)
check("V9 oversized request is rejected (413)", resp.status_code == 413)

# V10 sessions
cookie = new_user("dave").get("/dashboard").headers.get("Set-Cookie", "")
check("V10 session cookie is HttpOnly and SameSite=Strict",
      "HttpOnly" in cookie and "SameSite=Strict" in cookie)
old = new_user("erin")
with old.session_transaction() as s:
    s["login_at"] = time.time() - 9 * 3600
check("V10 session older than 8 hours is signed out", not logged_in(old))

# V11 CSV injection
post(alice, "/add_expense", category="Other", amount="1", date=TODAY,
     description="=cmd|' /C calc'!A0")
csv_text = alice.get("/export_csv").get_data(as_text=True)
check("V11 CSV cell starting with = is neutralised", "\"'=cmd" in csv_text)

# Extra web protections
before = count_expenses()
alice.post("/add_expense", data=dict(category="Food", amount="5", date=TODAY))
check("CSRF: a form without the secret token is rejected", count_expenses() == before)
headers = alice.get("/dashboard").headers
check("Security headers (CSP, no framing, nosniff) are set",
      "Content-Security-Policy" in headers and headers.get("X-Frame-Options") == "DENY"
      and headers.get("X-Content-Type-Options") == "nosniff")
post(alice, "/add_expense", category="Food", amount="3", date=TODAY,
     description='x" onfocus="alert(1)')
html = alice.get("/dashboard").get_data(as_text=True)
check("XSS: quotes in a description can't break out of the HTML",
      'onfocus="alert(1)' not in html and "x&#34; onfocus=&#34;alert(1)" in html)

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
