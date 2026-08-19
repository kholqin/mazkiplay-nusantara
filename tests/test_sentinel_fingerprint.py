import pytest

from app.sentinel.fingerprint import (
    classify_status,
    fingerprint_http,
)
from app.sentinel.models import HTTPObservation


def test_status_classification():
    assert classify_status(200) == "success"
    assert classify_status(301) == "redirect"
    assert classify_status(404) == "client-error"
    assert classify_status(500) == "server-error"
    assert classify_status(None) == "unknown"


def test_security_headers():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        },
    )

    result = fingerprint_http(
        observation
    )

    assert result.security_headers[
        "strict-transport-security"
    ]

    assert result.security_headers[
        "content-security-policy"
    ]

    assert result.security_headers[
        "x-content-type-options"
    ]

    assert not result.security_headers[
        "x-frame-options"
    ]


def test_cloudflare_detection():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        server="cloudflare",
        headers={
            "cf-ray": "abc123",
        },
    )

    result = fingerprint_http(
        observation
    )

    assert result.is_cdn_hint
    assert result.is_waf_hint

    names = {
        item.name
        for item in result.technologies
    }

    assert "Cloudflare" in names


def test_api_detection():
    observation = HTTPObservation(
        url="https://example.com/api/users",
        status_code=200,
        content_type="application/json",
    )

    result = fingerprint_http(
        observation
    )

    assert result.is_api_hint


def test_server_detection():
    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        server="nginx/1.27",
        headers={},
    )

    result = fingerprint_http(
        observation
    )

    names = {
        item.name
        for item in result.technologies
    }

    assert "nginx" in {
        name.lower()
        for name in names
    }
