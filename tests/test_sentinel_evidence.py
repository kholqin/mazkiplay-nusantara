from app.sentinel.evidence import (
    collect_http_evidence,
)
from app.sentinel.models import HTTPObservation


def test_collect_security_header_evidence():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        headers={
            "content-security-policy":
                "default-src 'self'",
            "x-content-type-options":
                "nosniff",
        },
    )

    evidence = collect_http_evidence(
        observation
    )

    ids = {
        item.evidence_id
        for item in evidence
    }

    assert (
        "header:content-security-policy"
        in ids
    )

    assert (
        "header:x-content-type-options"
        in ids
    )


def test_collect_server_evidence():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        server="nginx",
    )

    evidence = collect_http_evidence(
        observation
    )

    assert any(
        item.category == "technology"
        and item.value == "nginx"
        for item in evidence
    )


def test_collect_cookie_evidence():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        cookies=[
            "session",
            "csrf",
        ],
    )

    evidence = collect_http_evidence(
        observation
    )

    cookie_names = {
        item.metadata["cookie_name"]
        for item in evidence
        if item.category == "cookie"
    }

    assert cookie_names == {
        "session",
        "csrf",
    }


def test_collect_redirect_evidence():
    observation = HTTPObservation(
        url="http://example.com/",
        final_url="https://example.com/",
        status_code=200,
        redirects=[
            "http://example.com/",
            "https://example.com/",
        ],
    )

    evidence = collect_http_evidence(
        observation
    )

    redirects = [
        item.value
        for item in evidence
        if item.category == "redirect"
    ]

    assert (
        "http://example.com/"
        in redirects
    )

    assert (
        "https://example.com/"
        in redirects
    )


def test_empty_observation():
    observation = HTTPObservation(
        url="https://example.com/"
    )

    evidence = collect_http_evidence(
        observation
    )

    assert evidence == []


def test_collect_structured_cookie_evidence():
    from app.sentinel.models import (
        HTTPCookieObservation,
    )

    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        cookie_observations=[
            HTTPCookieObservation(
                name="session",
                value="abc",
                secure=True,
                httponly=True,
                samesite="lax",
                domain="example.com",
                path="/",
            )
        ],
    )

    evidence = collect_http_evidence(
        observation
    )

    cookie = next(
        item
        for item in evidence
        if item.category == "cookie"
    )

    assert cookie.metadata["cookie_name"] == "session"
    assert cookie.metadata["secure"] == "true"
    assert cookie.metadata["httponly"] == "true"
    assert cookie.metadata["samesite"] == "lax"
    assert cookie.metadata["domain"] == "example.com"
    assert cookie.metadata["path"] == "/"
