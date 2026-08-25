"""A small Notes app: list, view, create, search, log in, download attachments.

Kept deliberately plain so the security-relevant lines are easy to find. See the
README for the seams where vulnerabilities get introduced in later PRs.
"""

import os
from pathlib import Path

from flask import (Flask, abort, redirect, render_template, request, session,
                   url_for)
from jinja2 import select_autoescape
from werkzeug.security import check_password_hash

import db

UPLOADS = Path(__file__).parent / "uploads"

app = Flask(__name__)
# Dev-only fallback. Real deployments set NOTES_SECRET_KEY; a random key here means
# sessions simply do not survive a restart, which beats committing a fixed secret.
app.secret_key = os.environ.get("NOTES_SECRET_KEY") or os.urandom(32)
app.teardown_appcontext(db.close_db)

# Explicitly enable Jinja2 auto-escaping for all HTML/XML templates.
# This ensures that any database-sourced content rendered via {{ }} expressions
# is HTML-escaped before output, preventing stored XSS attacks (CWE-79).
app.jinja_env.autoescape = select_autoescape(
    enabled_extensions=("html", "htm", "xml"),
    disabled_extensions=("txt",),
    default_for_string=True,
    default=True,
)


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/")
def index():
    return render_template("index.html", notes=db.list_notes())


@app.route("/notes/<int:note_id>")
def view_note(note_id):
    note = db.get_note(note_id)
    if note is None:
        abort(404)
    return render_template("note.html", note=note)


@app.route("/notes", methods=["POST"])
def add_note():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title:
        return redirect(url_for("index"))
    return redirect(url_for("view_note", note_id=db.create_note(title, body)))


@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = db.search_notes(query) if query else []
    return render_template("search.html", query=query, results=results)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    user = db.find_user(request.form.get("username", ""))
    password = request.form.get("password", "")
    # check_password_hash is constant-time and handles the salt/algorithm prefix.
    if user is not None and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))
    return render_template("login.html", error="Invalid username or password."), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/attachments/<path:name>")
def attachment(name):
    """Serve a file from uploads/.

    The path is resolved and confirmed to sit under the uploads root *before* any
    read, so '../' sequences and absolute paths cannot escape the directory.
    """
    root = UPLOADS.resolve()
    try:
        target = (root / name).resolve()
    except (OSError, ValueError):
        abort(400)
    if not target.is_relative_to(root) or not target.is_file():
        abort(404)
    return target.read_bytes(), 200, {"Content-Type": "text/plain; charset=utf-8"}


db.init_db()

if __name__ == "__main__":
    # debug=False matters: the Werkzeug debugger is remote code execution.
    app.run(host="127.0.0.1", port=5000, debug=False)
