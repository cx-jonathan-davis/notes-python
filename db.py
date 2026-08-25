"""SQLite helpers for the Notes app.

Every statement here is parameterized. That is deliberate: this app is a clean
baseline for Checkmarx scanning, so an injection finding should only ever come
from a later change -- never from this file as written.
"""

import sqlite3
from pathlib import Path

from flask import g
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "notes.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the tables, and seed a demo user and notes on first run."""
    fresh = not DB_PATH.exists()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA_PATH.read_text())
    if fresh:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("demo", generate_password_hash("demo-password")),
        )
        conn.executemany(
            "INSERT INTO notes (title, body) VALUES (?, ?)",
            [
                ("Welcome", "This is a sample note. Try the search box above."),
                ("Shopping list", "Coffee, oat milk, bread."),
                ("Release checklist", "Run the tests, tag the commit, publish."),
            ],
        )
        conn.commit()
    conn.close()


def list_notes():
    return get_db().execute(
        "SELECT id, title, body, created_at FROM notes ORDER BY id DESC"
    ).fetchall()


def get_note(note_id):
    return get_db().execute(
        "SELECT id, title, body, created_at FROM notes WHERE id = ?", (note_id,)
    ).fetchone()


def create_note(title, body):
    db = get_db()
    cur = db.execute("INSERT INTO notes (title, body) VALUES (?, ?)", (title, body))
    db.commit()
    return cur.lastrowid


def search_notes(query):
    """Search titles and bodies.

    The LIKE wildcards are bound as part of the *parameter*, not spliced into the
    SQL text -- that is what keeps this safe.
    """
    like = f"%{query}%"
    return get_db().execute(
        "SELECT id, title, body, created_at FROM notes "
        "WHERE title LIKE ? OR body LIKE ? ORDER BY id DESC",
        (like, like),
    ).fetchall()


def find_user(username):
    return get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
