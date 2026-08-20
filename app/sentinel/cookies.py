from __future__ import annotations


from .models import HTTPCookieObservation


_SESSION_NAMES = {
    "session",
    "sessionid",
    "session_id",
    "sess",
    "sid",
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "asp.net_sessionid",
    "connect.sid",
}

_AUTH_NAMES = {
    "auth",
    "auth_token",
    "access_token",
    "id_token",
    "refresh_token",
    "token",
    "jwt",
    "authorization",
}

_CSRF_NAMES = {
    "csrf",
    "csrf_token",
    "csrftoken",
    "xsrf",
    "xsrf_token",
    "xsrf-token",
}

_PREFERENCE_NAMES = {
    "theme",
    "language",
    "locale",
    "preferences",
    "preferences_id",
}


def classify_cookie(name: str) -> str:
    """
    Classify a cookie by name only.

    This is heuristic intelligence, not proof that a cookie
    contains authentication material.
    """

    normalized = name.strip().lower()

    if normalized in _SESSION_NAMES:
        return "session"

    if normalized in _AUTH_NAMES:
        return "authentication"

    if normalized in _CSRF_NAMES:
        return "csrf"

    if normalized in _PREFERENCE_NAMES:
        return "preference"

    if (
        "session" in normalized
        or normalized.endswith("_sid")
        or normalized.endswith("-sid")
    ):
        return "session"

    if (
        "csrf" in normalized
        or "xsrf" in normalized
    ):
        return "csrf"

    if (
        "token" in normalized
        or normalized.endswith("_jwt")
        or normalized.endswith("-jwt")
    ):
        return "authentication"

    return "unknown"


def redact_cookie_value(
    value: str | None,
) -> str:
    """
    Prevent session/authentication material from appearing
    in reports or findings.

    Length is intentionally not returned because even token
    length can be unnecessary sensitive information.
    """

    if value is None:
        return "[REDACTED]"

    if value == "":
        return "[EMPTY]"

    return "[REDACTED]"


def cookie_metadata(
    cookie: HTTPCookieObservation,
) -> dict[str, str]:
    """
    Produce safe, reportable cookie metadata without exposing
    the cookie value.
    """

    return {
        "cookie_name": cookie.name,
        "role": classify_cookie(cookie.name),
        "secure": str(cookie.secure).lower(),
        "httponly": str(cookie.httponly).lower(),
        "samesite": cookie.samesite or "",
        "domain": cookie.domain or "",
        "path": cookie.path or "",
        "max_age": cookie.max_age or "",
        "expires": cookie.expires or "",
        "value": redact_cookie_value(cookie.value),
    }


def looks_like_sensitive_cookie(
    cookie: HTTPCookieObservation,
) -> bool:
    return classify_cookie(cookie.name) in {
        "session",
        "authentication",
        "csrf",
    }
