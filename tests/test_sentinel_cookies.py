from app.sentinel.cookies import (
    classify_cookie,
    cookie_metadata,
    looks_like_sensitive_cookie,
    redact_cookie_value,
)
from app.sentinel.models import HTTPCookieObservation


def test_classify_session_cookie():
    assert classify_cookie("PHPSESSID") == "session"
    assert classify_cookie("session_id") == "session"


def test_classify_auth_cookie():
    assert classify_cookie("access_token") == "authentication"
    assert classify_cookie("jwt") == "authentication"


def test_classify_csrf_cookie():
    assert classify_cookie("csrftoken") == "csrf"
    assert classify_cookie("XSRF-TOKEN") == "csrf"


def test_classify_preference_cookie():
    assert classify_cookie("theme") == "preference"


def test_unknown_cookie():
    assert classify_cookie("tracking_id") == "unknown"


def test_cookie_value_is_redacted():
    assert redact_cookie_value("super-secret-session-token") == "[REDACTED]"
    assert redact_cookie_value(None) == "[REDACTED]"
    assert redact_cookie_value("") == "[EMPTY]"


def test_cookie_metadata_does_not_expose_value():
    cookie = HTTPCookieObservation(
        name="session",
        value="super-secret-token",
        secure=True,
        httponly=True,
        samesite="lax",
        path="/",
    )

    metadata = cookie_metadata(cookie)

    assert metadata["role"] == "session"
    assert metadata["secure"] == "true"
    assert metadata["httponly"] == "true"
    assert metadata["value"] == "[REDACTED]"
    assert "super-secret-token" not in str(metadata)


def test_sensitive_cookie_detection():
    session = HTTPCookieObservation(
        name="session",
        value="abc",
    )

    preference = HTTPCookieObservation(
        name="theme",
        value="dark",
    )

    assert looks_like_sensitive_cookie(session)
    assert not looks_like_sensitive_cookie(preference)
