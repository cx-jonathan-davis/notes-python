"""Tests for HTTP security headers and CSRF protection.

These tests verify that:
1. Every response includes a valid Strict-Transport-Security (HSTS) header.
2. The HSTS value meets minimum security requirements (max-age >= 1 year,
   includeSubDomains present).
3. No endpoint accidentally omits the header.
4. All state-altering POST endpoints are protected by a CSRF synchronizer token
   (CWE-352) — requests without a valid token are rejected with HTTP 400.
5. CSRF protection is enforced by the centralised before_request hook (csrf_protect)
   so no individual view can accidentally omit the check.
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


# ---------------------------------------------------------------------------
# CSRF token generation and helpers
# ---------------------------------------------------------------------------

def _get_session_csrf_token(client):
    """Obtain the CSRF token by performing a GET to /login.

    The GET request triggers _get_csrf_token() which stores the token in the
    session cookie; the Flask test client persists the cookie for subsequent
    requests.
    """
    client.get("/login")
    with client.session_transaction() as sess:
        return sess.get("csrf_token", "")


# ---------------------------------------------------------------------------
# CSRF protection — login endpoint (CWE-352)
# ---------------------------------------------------------------------------

class TestLoginCSRFProtection:
    """The /login POST endpoint must reject requests without a valid CSRF token."""

    def test_login_post_without_csrf_token_returns_400(self, client):
        """POST /login with no csrf_token field must be rejected (HTTP 400)."""
        response = client.post(
            "/login",
            data={"username": "demo", "password": "demo-password"},
        )
        assert response.status_code == 400, (
            "Expected HTTP 400 when no CSRF token is submitted to /login"
        )

    def test_login_post_with_wrong_csrf_token_returns_400(self, client):
        """POST /login with an incorrect CSRF token must be rejected (HTTP 400)."""
        # Seed the session with a real token so the session exists.
        _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": "totally-wrong-token",
            },
        )
        assert response.status_code == 400, (
            "Expected HTTP 400 when a wrong CSRF token is submitted to /login"
        )

    def test_login_post_with_valid_csrf_token_succeeds(self, client):
        """POST /login with a valid CSRF token must be processed (not rejected with 400)."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": token,
            },
        )
        # A valid login redirects to index (302), an invalid credential returns 401,
        # but either way the CSRF check must pass (status must not be 400).
        assert response.status_code != 400, (
            "Valid CSRF token must not be rejected by the login endpoint"
        )

    def test_login_post_with_empty_csrf_token_returns_400(self, client):
        """POST /login with an empty csrf_token string must be rejected (HTTP 400)."""
        _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": "",
            },
        )
        assert response.status_code == 400

    def test_login_get_does_not_require_csrf_token(self, client):
        """GET /login must succeed without any CSRF token (read-only, no state change)."""
        response = client.get("/login")
        assert response.status_code == 200

    def test_login_form_contains_csrf_token_field(self, client):
        """The login page HTML must include a hidden csrf_token input field."""
        response = client.get("/login")
        assert b'name="csrf_token"' in response.data, (
            "The rendered login form must include a hidden csrf_token input"
        )

    def test_login_csrf_token_is_non_empty_in_session(self, client):
        """After GET /login the session must contain a non-empty csrf_token."""
        token = _get_session_csrf_token(client)
        assert token, "Session csrf_token must not be empty after GET /login"

    def test_successful_login_redirects_to_index(self, client):
        """A POST /login with correct credentials AND a valid token redirects to /."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": token,
            },
        )
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/")

    def test_failed_login_returns_401(self, client):
        """A POST /login with wrong credentials AND a valid token returns 401."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "wrong-password",
                "csrf_token": token,
            },
        )
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# CSRF protection — add_note endpoint
# ---------------------------------------------------------------------------

class TestAddNoteCSRFProtection:
    """The /notes POST endpoint must reject requests without a valid CSRF token."""

    def test_add_note_without_csrf_token_returns_400(self, client):
        """POST /notes with no csrf_token must be rejected (HTTP 400)."""
        response = client.post(
            "/notes",
            data={"title": "Injected note", "body": "CSRF body"},
        )
        assert response.status_code == 400

    def test_add_note_with_wrong_csrf_token_returns_400(self, client):
        """POST /notes with an incorrect CSRF token must be rejected (HTTP 400)."""
        _get_session_csrf_token(client)
        response = client.post(
            "/notes",
            data={
                "title": "Injected note",
                "body": "CSRF body",
                "csrf_token": "attacker-controlled-token",
            },
        )
        assert response.status_code == 400

    def test_add_note_with_valid_csrf_token_succeeds(self, client):
        """POST /notes with a valid CSRF token must be processed (redirect, not 400)."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/notes",
            data={
                "title": "Legitimate note",
                "body": "Created with valid CSRF token",
                "csrf_token": token,
            },
        )
        assert response.status_code == 302

    def test_add_note_form_contains_csrf_token_field(self, client):
        """The index page HTML must include a hidden csrf_token input in the note form."""
        response = client.get("/")
        assert b'name="csrf_token"' in response.data, (
            "The rendered add-note form must include a hidden csrf_token input"
        )


# ---------------------------------------------------------------------------
# CSRF protection — logout endpoint
# ---------------------------------------------------------------------------

class TestLogoutCSRFProtection:
    """The /logout POST endpoint must reject requests without a valid CSRF token."""

    def test_logout_without_csrf_token_returns_400(self, client):
        """POST /logout with no csrf_token must be rejected (HTTP 400)."""
        response = client.post("/logout")
        assert response.status_code == 400

    def test_logout_with_wrong_csrf_token_returns_400(self, client):
        """POST /logout with a wrong CSRF token must be rejected (HTTP 400)."""
        _get_session_csrf_token(client)
        response = client.post(
            "/logout",
            data={"csrf_token": "wrong-token"},
        )
        assert response.status_code == 400

    def test_logout_with_valid_csrf_token_redirects(self, client):
        """POST /logout with a valid CSRF token must succeed (redirect, not 400)."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/logout",
            data={"csrf_token": token},
        )
        assert response.status_code == 302

    def test_logout_form_in_base_template_contains_csrf_token(self, client):
        """The base template's logout form must include a hidden csrf_token input."""
        # First log in so the logout form is rendered.
        token = _get_session_csrf_token(client)
        client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": token,
            },
        )
        # Re-fetch the token after login (session was cleared and new session started).
        with client.session_transaction() as sess:
            new_token = sess.get("csrf_token", "")
        # The index page (which uses base.html) must contain the csrf_token hidden field.
        response = client.get("/")
        assert b'name="csrf_token"' in response.data, (
            "The base template logout form must include a hidden csrf_token input "
            "when the user is logged in"
        )
        assert new_token.encode() in response.data, (
            "The CSRF token value in the rendered page must match the session token"
        )


# ---------------------------------------------------------------------------
# CSRF token properties
# ---------------------------------------------------------------------------

class TestCSRFTokenProperties:
    """Verify the CSRF token implementation meets security requirements."""

    def test_csrf_token_has_sufficient_length(self, client):
        """The CSRF token must be at least 32 hex characters (128 bits of entropy)."""
        token = _get_session_csrf_token(client)
        assert len(token) >= 32, (
            f"CSRF token length {len(token)} is below the 32-character minimum"
        )

    def test_csrf_token_is_hexadecimal(self, client):
        """The CSRF token must consist of hexadecimal characters only."""
        token = _get_session_csrf_token(client)
        assert all(c in "0123456789abcdef" for c in token), (
            "CSRF token must be a hexadecimal string (output of secrets.token_hex)"
        )

    def test_csrf_token_is_stable_within_session(self, client):
        """Multiple GET requests within the same session must return the same token."""
        token1 = _get_session_csrf_token(client)
        token2 = _get_session_csrf_token(client)
        assert token1 == token2, (
            "The CSRF token must remain stable within a single session"
        )

    def test_csrf_helper_functions_registered(self):
        """_get_csrf_token and _validate_csrf must exist on the app module."""
        assert hasattr(app_module, "_get_csrf_token"), (
            "_get_csrf_token helper is missing from app module"
        )
        assert hasattr(app_module, "_validate_csrf"), (
            "_validate_csrf helper is missing from app module"
        )

    def test_csrf_token_in_jinja_globals(self):
        """csrf_token must be registered as a Jinja2 global so templates can use it."""
        assert "csrf_token" in app_module.app.jinja_env.globals, (
            "csrf_token must be registered in app.jinja_env.globals"
        )


# ---------------------------------------------------------------------------
# Centralised CSRF before_request hook (CWE-352 remediation)
# ---------------------------------------------------------------------------

class TestCsrfProtectBeforeRequestHook:
    """The centralised csrf_protect before_request hook must be wired up and enforce
    CSRF validation for ALL state-altering HTTP methods before any route handler runs.

    This verifies the fix for CWE-352: the synchronizer token is enforced at the
    application boundary (before_request) rather than inside individual route handlers,
    so no handler can accidentally bypass it.
    """

    def test_csrf_protect_hook_registered(self):
        """csrf_protect must appear in Flask's before_request_funcs list."""
        hook_names = [
            f.__name__
            for f in app_module.app.before_request_funcs.get(None, [])
        ]
        assert "csrf_protect" in hook_names, (
            "csrf_protect is not registered as a before_request hook. "
            "CSRF protection would rely solely on per-handler calls and could be bypassed."
        )

    def test_login_post_rejected_without_csrf_via_before_request_hook(self, client):
        """POST /login with no token is rejected by the before_request hook (HTTP 400).

        This specifically validates that the before_request hook fires before the
        login handler attempts to process credentials.
        """
        response = client.post(
            "/login",
            data={"username": "demo", "password": "demo-password"},
        )
        assert response.status_code == 400, (
            "before_request csrf_protect hook must reject /login POST without token"
        )

    def test_csrf_protect_rejects_put_method(self, client):
        """The hook must reject PUT requests without a valid CSRF token (HTTP 400).

        PUT is a state-altering method — the hook must cover it even if no current
        route uses PUT, to guard against future additions.
        """
        _get_session_csrf_token(client)
        response = client.put("/notes/1", data={"title": "hacked"})
        # Either 400 (CSRF rejection) or 404/405 (no such route / method not allowed)
        # are both acceptable — the key invariant is that it is NOT 200/302.
        assert response.status_code in (400, 404, 405), (
            "PUT without CSRF token must not succeed (expected 400, 404, or 405)"
        )

    def test_csrf_protect_rejects_delete_method(self, client):
        """The hook must reject DELETE requests without a valid CSRF token (HTTP 400)."""
        _get_session_csrf_token(client)
        response = client.delete("/notes/1")
        assert response.status_code in (400, 404, 405), (
            "DELETE without CSRF token must not succeed (expected 400, 404, or 405)"
        )

    def test_csrf_protect_allows_get_method(self, client):
        """GET requests must not be blocked by the CSRF hook (safe method)."""
        response = client.get("/login")
        assert response.status_code == 200, (
            "GET /login must not be blocked by the CSRF before_request hook"
        )

    def test_csrf_protect_allows_post_with_valid_token(self, client):
        """POST /login with a valid token must pass the before_request hook."""
        token = _get_session_csrf_token(client)
        response = client.post(
            "/login",
            data={
                "username": "demo",
                "password": "demo-password",
                "csrf_token": token,
            },
        )
        # Must not be rejected by the CSRF hook (400).
        assert response.status_code != 400, (
            "before_request csrf_protect must allow POST when a valid CSRF token is provided"
        )

    def test_login_handler_does_not_contain_inline_csrf_call(self):
        """The login view must NOT contain an explicit _validate_csrf() call.

        CSRF is now the responsibility of the before_request hook exclusively.
        Duplicating the check inside the handler is both redundant and increases
        the risk of drift if the hook is ever moved/renamed.
        """
        import inspect
        source = inspect.getsource(app_module.login)
        assert "_validate_csrf" not in source, (
            "login() should not call _validate_csrf() directly — "
            "CSRF validation is handled by the csrf_protect before_request hook"
        )

    def test_add_note_handler_does_not_contain_inline_csrf_call(self):
        """The add_note view must NOT contain an explicit _validate_csrf() call."""
        import inspect
        source = inspect.getsource(app_module.add_note)
        assert "_validate_csrf" not in source, (
            "add_note() should not call _validate_csrf() directly — "
            "CSRF validation is handled by the csrf_protect before_request hook"
        )

    def test_logout_handler_does_not_contain_inline_csrf_call(self):
        """The logout view must NOT contain an explicit _validate_csrf() call."""
        import inspect
        source = inspect.getsource(app_module.logout)
        assert "_validate_csrf" not in source, (
            "logout() should not call _validate_csrf() directly — "
            "CSRF validation is handled by the csrf_protect before_request hook"
        )
