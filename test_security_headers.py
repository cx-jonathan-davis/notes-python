"""Tests for HTTP security headers — specifically the HSTS header remediation.

These tests verify that:
1. Every response includes a valid Strict-Transport-Security (HSTS) header.
2. The HSTS value meets minimum security requirements (max-age >= 1 year,
   includeSubDomains present).
3. No endpoint accidentally omits the header.
"""

import pytest

import app as app_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Return a Flask test client with an isolated, in-memory database.

    We patch DB_PATH and SCHEMA_PATH so the test run never touches the real
    notes.db and doesn't depend on the working directory.
    """
    import db as db_module
    import sqlite3
    from pathlib import Path
    import os

    # Point the DB at a temp file so tests are isolated.
    test_db = tmp_path / "test_notes.db"
    monkeypatch.setattr(db_module, "DB_PATH", test_db)

    # Locate schema.sql relative to the app source.
    schema_path = Path(app_module.__file__).parent / "schema.sql"
    monkeypatch.setattr(db_module, "SCHEMA_PATH", schema_path)

    # Re-initialise the database for this test run.
    db_module.init_db()

    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test-secret"

    with app_module.app.test_client() as client:
        yield client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ONE_YEAR_SECONDS = 31536000


def assert_hsts_header(response):
    """Assert that the response carries a well-formed HSTS header."""
    hsts = response.headers.get("Strict-Transport-Security")
    assert hsts is not None, (
        "Strict-Transport-Security header is missing from the response"
    )

    # Parse directive tokens (case-insensitive per RFC 6797 §6.1).
    directives = [d.strip().lower() for d in hsts.split(";")]

    # Find and validate max-age.
    max_age_value = None
    for directive in directives:
        if directive.startswith("max-age="):
            try:
                max_age_value = int(directive.split("=", 1)[1])
            except ValueError:
                pytest.fail(
                    f"max-age directive in HSTS header has non-integer value: {hsts!r}"
                )
            break

    assert max_age_value is not None, (
        f"HSTS header missing max-age directive: {hsts!r}"
    )
    assert max_age_value >= _ONE_YEAR_SECONDS, (
        f"HSTS max-age {max_age_value} is less than the recommended 1-year minimum "
        f"({_ONE_YEAR_SECONDS})"
    )

    # includeSubDomains is required by our policy.
    assert "includesubdomains" in directives, (
        f"HSTS header missing 'includeSubDomains' directive: {hsts!r}"
    )


# ---------------------------------------------------------------------------
# HSTS header — present on every endpoint
# ---------------------------------------------------------------------------

class TestHSTSHeaderPresent:
    """Every HTTP response must carry a valid Strict-Transport-Security header."""

    def test_index_has_hsts(self, client):
        """GET / must include HSTS."""
        response = client.get("/")
        assert_hsts_header(response)

    def test_health_has_hsts(self, client):
        """GET /health must include HSTS."""
        response = client.get("/health")
        assert_hsts_header(response)

    def test_search_has_hsts(self, client):
        """GET /search must include HSTS."""
        response = client.get("/search?q=test")
        assert_hsts_header(response)

    def test_login_get_has_hsts(self, client):
        """GET /login must include HSTS."""
        response = client.get("/login")
        assert_hsts_header(response)

    def test_login_post_has_hsts(self, client):
        """POST /login (failed auth) must include HSTS."""
        response = client.post(
            "/login",
            data={"username": "nobody", "password": "wrong"},
        )
        assert_hsts_header(response)

    def test_add_note_redirect_has_hsts(self, client):
        """POST /notes (redirect) must include HSTS."""
        response = client.post(
            "/notes",
            data={"title": "Test note", "body": "Body text"},
        )
        # Redirects are still responses and must carry the header.
        assert_hsts_header(response)

    def test_404_response_has_hsts(self, client):
        """404 error responses must include HSTS."""
        response = client.get("/notes/999999")
        assert response.status_code == 404
        assert_hsts_header(response)

    def test_logout_has_hsts(self, client):
        """POST /logout must include HSTS."""
        response = client.post("/logout")
        assert_hsts_header(response)


# ---------------------------------------------------------------------------
# HSTS header — value quality checks
# ---------------------------------------------------------------------------

class TestHSTSHeaderValue:
    """The HSTS header value must meet RFC 6797 requirements."""

    def test_hsts_max_age_is_at_least_one_year(self, client):
        """max-age must be at least one year (31536000 seconds)."""
        response = client.get("/health")
        hsts = response.headers["Strict-Transport-Security"]
        directives = {
            d.strip().split("=", 1)[0].lower(): d.strip().split("=", 1)[1]
            if "=" in d else True
            for d in hsts.split(";")
        }
        max_age = int(directives["max-age"])
        assert max_age >= _ONE_YEAR_SECONDS

    def test_hsts_includes_subdomains(self, client):
        """includeSubDomains must be present to protect all subdomains."""
        response = client.get("/health")
        hsts = response.headers["Strict-Transport-Security"].lower()
        assert "includesubdomains" in hsts

    def test_hsts_header_is_single_value(self, client):
        """There should be exactly one Strict-Transport-Security header (no duplicates)."""
        response = client.get("/health")
        # Flask's Headers.getlist returns all values for a given key.
        hsts_values = response.headers.getlist("Strict-Transport-Security")
        assert len(hsts_values) == 1, (
            f"Expected exactly one HSTS header, found {len(hsts_values)}: {hsts_values}"
        )

    def test_hsts_max_age_is_numeric(self, client):
        """max-age value must be a valid non-negative integer per RFC 6797 §6.1."""
        response = client.get("/health")
        hsts = response.headers["Strict-Transport-Security"]
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                value = part.split("=", 1)[1]
                assert value.isdigit(), f"max-age is not a valid integer: {value!r}"
                assert int(value) >= 0
                break
        else:
            pytest.fail(f"max-age directive not found in HSTS header: {hsts!r}")


# ---------------------------------------------------------------------------
# Regression guard — set_security_headers hook must be registered
# ---------------------------------------------------------------------------

class TestSecurityHeadersHookRegistered:
    """Verify that the after_request hook is wired up on the Flask app."""

    def test_after_request_hook_registered(self):
        """The set_security_headers function must be in the after_request funcs list."""
        hook_names = [f.__name__ for f in app_module.app.after_request_funcs.get(None, [])]
        assert "set_security_headers" in hook_names, (
            "set_security_headers is not registered as an after_request hook. "
            "The HSTS header will never be sent."
        )
