"""Tests for stored XSS remediation (CWE-79) in the search results page.

The vulnerability: database-sourced note content (title, body) was rendered in
search.html without guaranteed HTML escaping, enabling stored XSS attacks.

The fix: explicit Jinja2 auto-escaping via ``select_autoescape`` in app.py, so
every {{ }} expression in .html templates is HTML-escaped before output.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_with_db(monkeypatch, tmp_path):
    """Create a fresh Flask app wired to a temporary SQLite database.

    Patches ``db.DB_PATH`` so each test gets an isolated, empty database.
    """
    import db as db_module

    # Point the module-level DB_PATH to a temp file for this test.
    tmp_db = tmp_path / "test_notes.db"
    monkeypatch.setattr(db_module, "DB_PATH", tmp_db)

    # Re-import app AFTER patching DB_PATH so init_db() uses the temp DB.
    # We must reload app because it calls db.init_db() at module level.
    import importlib
    import app as app_module

    importlib.reload(app_module)

    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test-secret"

    yield app_module.app

    # Cleanup: remove temp DB if it was created.
    if tmp_db.exists():
        tmp_db.unlink()


@pytest.fixture()
def client(app_with_db):
    """Return a Flask test client backed by the isolated test database."""
    return app_with_db.test_client()


@pytest.fixture()
def db_conn(app_with_db, tmp_path):
    """Return a direct SQLite connection to the test database for seeding."""
    import db as db_module

    conn = sqlite3.connect(db_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def seed_note(conn, title, body):
    """Insert a note directly into the database and return its row id."""
    cur = conn.execute(
        "INSERT INTO notes (title, body) VALUES (?, ?)", (title, body)
    )
    conn.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def search(client, query):
    """GET /search?q=<query> and return the response."""
    return client.get(f"/search?q={query}")


# ---------------------------------------------------------------------------
# Auto-escaping configuration tests
# ---------------------------------------------------------------------------


class TestAutoEscapeConfiguration:
    """Verify that Jinja2 auto-escaping is explicitly enabled in the app."""

    def test_autoescape_callable_is_set(self, app_with_db):
        """app.jinja_env.autoescape must be a callable (from select_autoescape)."""
        assert callable(app_with_db.jinja_env.autoescape), (
            "app.jinja_env.autoescape should be a callable produced by "
            "jinja2.select_autoescape, not a plain bool."
        )

    def test_autoescape_enabled_for_html(self, app_with_db):
        """HTML templates must have auto-escaping enabled."""
        autoescape = app_with_db.jinja_env.autoescape
        # select_autoescape returns a function that takes a template name.
        assert autoescape("search.html") is True
        assert autoescape("index.html") is True
        assert autoescape("note.html") is True
        assert autoescape("base.html") is True

    def test_autoescape_enabled_for_htm(self, app_with_db):
        """The .htm extension should also be auto-escaped."""
        assert app_with_db.jinja_env.autoescape("page.htm") is True

    def test_autoescape_enabled_for_xml(self, app_with_db):
        """The .xml extension should also be auto-escaped."""
        assert app_with_db.jinja_env.autoescape("feed.xml") is True


# ---------------------------------------------------------------------------
# Stored XSS prevention tests — search results page
# ---------------------------------------------------------------------------


class TestSearchXSSPrevention:
    """Ensure malicious HTML/JS stored in note fields is escaped in search output."""

    def test_script_tag_in_title_is_escaped(self, client, db_conn):
        """A <script> tag stored as a note title must be HTML-escaped, not executed."""
        xss_title = "<script>alert('xss')</script>"
        seed_note(db_conn, xss_title, "safe body")

        response = search(client, "script")

        assert response.status_code == 200
        html = response.data.decode("utf-8")

        # The raw tag must NOT appear verbatim in the output.
        assert "<script>alert('xss')</script>" not in html, (
            "Raw <script> tag found in search output — XSS not prevented."
        )
        # The escaped form MUST be present (Jinja2 auto-escape).
        assert "&lt;script&gt;" in html or "&#x3C;script&#x3E;" in html or (
            "alert" not in html
        ), "Title content was neither escaped nor omitted."

    def test_script_tag_in_body_is_escaped(self, client, db_conn):
        """A <script> tag stored as note body must be HTML-escaped in search results."""
        xss_body = "<script>document.cookie='stolen'</script>"
        seed_note(db_conn, "normal title", xss_body)

        response = search(client, "normal")

        assert response.status_code == 200
        html = response.data.decode("utf-8")

        assert "<script>document.cookie='stolen'</script>" not in html, (
            "Raw <script> tag found in body output — stored XSS not prevented."
        )

    def test_img_onerror_in_title_is_escaped(self, client, db_conn):
        """An img onerror payload in the title must be escaped."""
        payload = "<img src=x onerror=alert(1)>"
        seed_note(db_conn, payload, "body text")

        response = search(client, "body")

        html = response.data.decode("utf-8")
        # The literal unescaped img tag must not be present.
        assert "<img src=x onerror=alert(1)>" not in html, (
            "Unescaped <img onerror> tag found in output."
        )

    def test_javascript_uri_in_title_is_escaped(self, client, db_conn):
        """A javascript: URI stored in a title must be HTML-escaped."""
        payload = '<a href="javascript:alert(1)">click me</a>'
        seed_note(db_conn, payload, "body")

        response = search(client, "click")

        html = response.data.decode("utf-8")
        assert 'href="javascript:alert(1)"' not in html, (
            "Unescaped javascript: URI found in output."
        )

    def test_double_quote_in_title_is_escaped(self, client, db_conn):
        """Double quotes in note titles must be escaped to prevent attribute injection."""
        # Attempt to break out of an HTML attribute context.
        payload = '" onmouseover="alert(1)"'
        seed_note(db_conn, payload, "body")

        response = search(client, "body")

        html = response.data.decode("utf-8")
        assert 'onmouseover="alert(1)"' not in html, (
            "Unescaped attribute-injection payload found in output."
        )

    def test_angle_brackets_in_body_are_escaped(self, client, db_conn):
        """Angle brackets in note body must render as &lt;/&gt; entities."""
        seed_note(db_conn, "brackets note", "<b>bold</b>")

        response = search(client, "brackets")

        html = response.data.decode("utf-8")
        # The raw tag must not appear unescaped.
        assert "<b>bold</b>" not in html, (
            "Raw HTML tags in body are not escaped."
        )
        # Escaped form must appear.
        assert "&lt;b&gt;" in html or "&#x3C;b&#x3E;" in html

    def test_safe_note_still_rendered(self, client, db_conn):
        """Normal note content without special characters renders correctly."""
        seed_note(db_conn, "My safe note", "This is fine content.")

        response = search(client, "safe")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "My safe note" in html
        assert "This is fine content." in html

    def test_search_returns_result_count(self, client, db_conn):
        """Search results page correctly reports the number of matching notes."""
        seed_note(db_conn, "alpha note", "first result")
        seed_note(db_conn, "beta note", "second result")

        response = search(client, "note")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "2 result" in html

    def test_empty_search_shows_prompt(self, client):
        """With no query string the page invites the user to search."""
        response = client.get("/search")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Type something" in html

    def test_no_match_shows_nothing_matched(self, client, db_conn):
        """A search that matches no notes displays the 'Nothing matched' message."""
        seed_note(db_conn, "Unrelated note", "Content here.")

        response = search(client, "zzznomatch")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "Nothing matched" in html or "0 result" in html


# ---------------------------------------------------------------------------
# XSS prevention tests — other pages that render database content
# ---------------------------------------------------------------------------


class TestIndexPageXSSPrevention:
    """The index page also renders note title/body; confirm escaping there too."""

    def test_script_in_title_escaped_on_index(self, client, db_conn):
        """Script tag in a note title must be escaped on the index page."""
        seed_note(db_conn, "<script>evil()</script>", "body")

        response = client.get("/")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "<script>evil()</script>" not in html


class TestNotePageXSSPrevention:
    """The note detail page renders a single note; confirm escaping applies."""

    def test_script_in_body_escaped_on_note_page(self, client, db_conn):
        """Script tag in note body must be escaped on the individual note page."""
        note_id = seed_note(db_conn, "Safe title", "<script>steal()</script>")

        response = client.get(f"/notes/{note_id}")

        assert response.status_code == 200
        html = response.data.decode("utf-8")
        assert "<script>steal()</script>" not in html
