# notes-python

A small Flask + SQLite "Notes" app. It exists to be a **clean baseline** for Checkmarx
scanning: intentionally vulnerable PRs get opened against it later, and every finding they
produce should be attributable to the PR rather than to this starting point.

Sibling repos `notes-node` and `notes-java` implement the same routes, so a vulnerability
introduced here has a direct counterpart in the other two.

## Running it

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py     # http://127.0.0.1:5000
```

The SQLite database is created and seeded on first start. Demo account: `demo` / `demo-password`.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | List all notes, plus the "add note" form |
| `GET /notes/<id>` | View a single note |
| `POST /notes` | Create a note (`title`, `body`) |
| `GET /search?q=` | Search titles and bodies |
| `GET /login`, `POST /login` | Session login |
| `POST /logout` | Clear the session |
| `GET /attachments/<name>` | Serve a file from `uploads/` |
| `GET /health` | Liveness probe |

## Seams for vulnerability injection

Each route below is written securely *now*. The right-hand column is where a later PR would
introduce the corresponding flaw — listed so the three language repos stay in sync.

| Seam | File / function | Currently | Flaw a PR would introduce |
|---|---|---|---|
| SQL | `db.py:search_notes()` | Bound `?` parameters, wildcards in the value | SQL injection via f-string concatenation |
| SQL | `db.py:get_note()` | Bound `?` parameter | SQL injection on the id |
| HTML | `templates/index.html`, `note.html` | Jinja2 auto-escaping on | Stored XSS via `\| safe` or `Markup()` |
| Filesystem | `app.py:attachment()` | Resolves, then checks `is_relative_to(root)` | Path traversal by dropping the containment check |
| Secrets | `app.py` `secret_key` | Read from `NOTES_SECRET_KEY`, random fallback | Hardcoded secret key |
| Crypto | `app.py:login()` | `check_password_hash` (constant-time, salted) | Plaintext or MD5/SHA1 password comparison |
| Config | `app.py:__main__` | `debug=False` | `debug=True` — Werkzeug debugger is RCE |

## Why it is written this way

- **Parameterized statements everywhere.** No SQL string is ever built by concatenation.
- **Auto-escaping left on.** No `\| safe` filters anywhere in `templates/`.
- **Path containment before read.** `attachment()` resolves the path and confirms it sits
  under `uploads/` *before* opening it, so `../` and absolute paths both fail closed.
- **No committed secrets.** The session key comes from the environment.
- **Pinned dependencies**, so SCA results are reproducible.
