import httpx

from modules.redirects import (
    REDIRECT_CODES,
    _origin,
    check_redirect_chain,
)


def make_response(
    history: list[httpx.Response] | None = None,
    final_url: str = "https://example.com/final",
) -> httpx.Response:
    return httpx.Response(
        200,
        headers={},
        request=httpx.Request("GET", final_url),
        history=history or [],
    )


def make_redirect(
    status_code: int,
    url: str,
    location: str | None = None,
) -> httpx.Response:
    headers = {}

    if location is not None:
        headers["location"] = location

    return httpx.Response(
        status_code,
        headers=headers,
        request=httpx.Request("GET", url),
    )


def test_no_redirects_returns_no_findings():
    response = make_response()

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    assert findings == []


def test_origin_parsing():
    assert _origin("HTTPS://Example.COM/path") == (
        "https",
        "example.com",
        None,
    )


def test_origin_with_port():
    assert _origin("https://example.com:8443/test") == (
        "https",
        "example.com",
        8443,
    )


def test_redirect_chain_info():
    history = [
        make_redirect(
            301,
            "https://example.com/",
            "/login",
        )
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "redirect-chain-info" in ids


def test_long_redirect_chain():
    history = [
        make_redirect(301, "https://example.com/a", "/b"),
        make_redirect(302, "https://example.com/b", "/c"),
        make_redirect(303, "https://example.com/c", "/d"),
        make_redirect(307, "https://example.com/d", "/e"),
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "long-redirect-chain" in ids

    finding = next(
        finding
        for finding in findings
        if finding.id == "long-redirect-chain"
    )

    assert finding.metadata["redirect_count"] == 4


def test_external_redirect():
    history = [
        make_redirect(
            302,
            "https://example.com/",
            "https://evil.example/login",
        )
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "external-redirect" in ids

    finding = next(
        finding
        for finding in findings
        if finding.id == "external-redirect"
    )

    assert (
        "https://evil.example/login"
        in finding.metadata["external_destinations"]
    )


def test_same_origin_redirect_is_not_external():
    history = [
        make_redirect(
            301,
            "https://example.com/",
            "/dashboard",
        )
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "external-redirect" not in ids
    assert "redirect-chain-info" in ids


def test_redirect_without_location():
    history = [
        make_redirect(
            302,
            "https://example.com/",
        )
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "redirect-chain-info" in ids
    assert "external-redirect" not in ids


def test_redirect_codes_constant():
    assert REDIRECT_CODES == {
        301,
        302,
        303,
        307,
        308,
    }


def test_malformed_redirect_location_is_handled():
    history = [
        make_redirect(
            302,
            "https://example.com/",
            "://malformed-url",
        )
    ]

    response = make_response(history)

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "redirect-chain-info" in ids
    assert "external-redirect" in ids


def test_redirect_destination_exception_is_ignored(monkeypatch):
    history = [
        make_redirect(
            302,
            "https://example.com/",
            "/login",
        )
    ]

    response = make_response(history)

    def raise_url_error(*args, **kwargs):
        raise ValueError("simulated invalid URL")

    monkeypatch.setattr(
        "modules.redirects.httpx.URL",
        raise_url_error,
    )

    findings = check_redirect_chain(
        response,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "external-redirect" not in ids
    assert "redirect-chain-info" in ids
