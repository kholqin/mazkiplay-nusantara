import httpx

from modules.cookies import check_cookies


def make_response(*cookies: str) -> httpx.Response:
    headers = [
        ("set-cookie", cookie)
        for cookie in cookies
    ]

    return httpx.Response(
        200,
        headers=headers,
        request=httpx.Request(
            "GET",
            "https://example.com/",
        ),
    )


def test_no_cookies_returns_no_findings():
    response = make_response()

    assert check_cookies(response) == []


def test_missing_cookie_security_attributes():
    response = make_response(
        "session=abc123"
    )

    findings = check_cookies(response)
    ids = {finding.id for finding in findings}

    assert "cookie-missing-secure-1" in ids
    assert "cookie-missing-httponly-1" in ids
    assert "cookie-missing-samesite-1" in ids


def test_secure_httponly_samesite_cookie():
    response = make_response(
        "session=abc123; Secure; HttpOnly; SameSite=Lax"
    )

    findings = check_cookies(response)

    assert findings == []


def test_samesite_none_requires_secure():
    response = make_response(
        "session=abc123; HttpOnly; SameSite=None"
    )

    findings = check_cookies(response)
    ids = {finding.id for finding in findings}

    assert "cookie-samesite-none-without-secure-1" in ids


def test_invalid_samesite_value():
    response = make_response(
        "session=abc123; Secure; HttpOnly; SameSite=Invalid"
    )

    findings = check_cookies(response)
    ids = {finding.id for finding in findings}

    assert "cookie-invalid-samesite-1" in ids
