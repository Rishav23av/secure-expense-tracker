# Secure Daily Expense Tracker

A secure, full-featured expense tracker built with **Python Flask** and **SQLite**.

## Features

- **User accounts** — register/login with bcrypt-hashed passwords
- **Expense management** — add, edit, delete expenses across 6 categories
- **Spending analytics** — Chart.js charts (by category + over time)
- **CSV export** — download all your data anytime
- **Dark mode** — toggled and persisted via `localStorage`
- **Sortable table** — click any column header to sort
- **Date/category filter** — narrow down expenses

## Security features

| Threat | Defence |
|--------|---------|
| SQL injection | All queries use `?` parameterised placeholders — never string formatting |
| XSS | Raw text stored in DB; Jinja2 auto-escapes `{{ }}` at render time |
| Category injection | Server-side whitelist (`ALLOWED_CATEGORIES`) |
| Invalid amounts | `validate_amount()` — positive float, capped at $1,000,000 |
| Invalid dates | `validate_date()` — `strptime` strict `%Y-%m-%d` |
| Session fixation | `session.clear()` before setting new session on login |
| User isolation | Every query filters by both `id` **AND** `user_id` |
| User enumeration | Same error message for wrong user and wrong password |
| Brute force | Failed login attempts logged to `failed_logins` table |

### SQL Injection Demo

Try entering `Food'; DROP TABLE expenses; --` as an expense description.
It is stored and displayed safely as plain text — parameterised queries treat
special characters as data, not SQL syntax.

## Run locally

```bash
pip install flask
python app.py
# Visit http://127.0.0.1:8080
```

## Tech stack

- **Backend**: Python 3, Flask 2.3+, SQLite3, Werkzeug (bcrypt)
- **Frontend**: Vanilla JS, Chart.js 4.4.1 (cdnjs), Inter (Google Fonts)
- **Design**: Slate/Emerald palette, 8px spacing grid, layered shadows
