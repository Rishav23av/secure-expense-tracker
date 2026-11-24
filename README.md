# Secure Daily Expense Tracker

A small web app for recording daily expenses, built with **Python (Flask)** and **SQLite**
to show secure coding in practice. Every control below matches a risk (V1–V12) from our
*Security Design and Vulnerability Documentation* (STRIDE + DREAD).

## Run it

```bash
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:8080**, create an account (password of at least 12 characters) and sign in.

Run the security checks:

```bash
python3 test_security.py
```

## Features

- Register, sign in, sign out
- Add, edit, delete expenses (Food, Travel, Education, Shopping, Medical, Other)
- Filter by date and category, sort any column
- Charts by category and by month, CSV export, dark mode

## How each risk is handled

| ID | Risk | What the app does |
|----|------|-------------------|
| V1 | SQL injection | Every query uses `?` placeholders; input is never pasted into SQL |
| V2 | Weak password storage | Salted, slow hash (scrypt via Werkzeug); plain passwords are never stored |
| V3 | Brute-force login | 5 wrong passwords lock the username for 15 minutes; one message for every failure |
| V4 | Seeing or changing other users' data | Every query also checks `user_id`; someone else's expense is just "not found" |
| V5 | Bad input | Amount must be > 0, ≤ 1,000,000, max 2 decimals; category from a fixed list; real date, not in the future; description ≤ 500 characters. The database has `CHECK` rules too |
| V6 | Leaking errors | Users see only "Something went wrong. Reference: abc123"; details go to `logs/app.log`; debug mode is off |
| V7 | Secrets in code | The secret key comes from the `SECRET_KEY` environment variable (or a random one at start-up) |
| V8 | No audit trail | `audit_log` table records sign-ins, failures, adds, edits, deletes and exports. Triggers stop anyone editing or deleting it |
| V9 | Resource exhaustion | Requests over 16 KB are rejected; text length limits |
| V10 | Weak sessions | Signed cookie, `HttpOnly`, `SameSite=Strict`, new session on login, 15 min idle and 8 h maximum |
| V11 | CSV formula injection | Cells starting with `= + - @` get a `'` in front so Excel won't run them |
| V12 | Vulnerable libraries | Versions pinned in `requirements.txt`; check with `pip install pip-audit && pip-audit` |

Extra web protections: a secret CSRF token on every form, security headers
(Content-Security-Policy, no framing, nosniff), and page text is always escaped,
so things like `<script>` show up as plain text.

### Try the SQL injection demo

Add an expense with the description `Food'; DROP TABLE expenses; --`.
It is saved and shown as plain text, and the table is still there.

## Known limitations

- **No HTTPS.** Meant for `localhost`. On a real network it must sit behind HTTPS.
- **Database file isn't encrypted.** It's protected only by file permissions.
- **Lockout is per username,** so someone could lock another person out for 15 minutes on purpose.
- **Sign-out clears the browser's cookie;** a copied cookie stays valid until its 15-minute timeout.

## Project files

```
app.py              routes, validation and all security controls
test_security.py    21 automated checks from the verification plan
templates/          base layout, login, register, dashboard
requirements.txt    pinned Flask and Werkzeug versions
```
