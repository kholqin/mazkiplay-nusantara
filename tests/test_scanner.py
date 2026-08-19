import httpx
import pytest

from app.config import ScannerConfig
from app.models import Finding, Severity
from app.scanner import WebScanner


def make_config(**overrides):
    values = {
        "timeout": 5.0,
        "connect_timeout": 5.0,
        "read_timeout": 5.0,
        "write_timeout": 5.0,
        "pool_timeout": 5.0,
        "concurrency": 5,
        "follow_redirects": True,
        "max_redirects": 5,
        "verify_tls": True,
        "user_agent": "Mazkiplay-Test",
        "enable_headers": False,
        "enable_cookies": False,
        "enable_cors": False,
        "enable_csp": False,
        "enable_disclosure": False,
        "enable_redirects": False,
        "enable_robots": False,
        "enable_sitemap": False,
        "enable_crawler": False,
        "max_sitemap_urls": 100,
        "max_pages": 10,
        "request_delay": 0.0,
    }

    values.update(overrides)
    return ScannerConfig(**values)


def make_response(
    url="https://example.com/",
    status_code=200,
    headers=None,
):
    return httpx.Response(
        status_code,
        headers=headers or {},
        request=httpx.Request("GET", url),
    )


@pytest.mark.asyncio
async def test_invalid_target_scheme():
    scanner = WebScanner(make_config())

    try:
        findings, requests_made, pages_scanned = await scanner.scan(
            "ftp://example.com/"
        )

        assert requests_made == 0
        assert pages_scanned == 0
        assert len(findings) == 1

        assert findings[0].id == "invalid-target-scheme"
        assert findings[0].severity == Severity.INFO

    finally:
        await scanner.close()


@pytest.mark.asyncio
async def test_primary_request_failure(monkeypatch):
    scanner = WebScanner(make_config())

    async def fake_get(url):
        raise httpx.ConnectError("connection failed")

    monkeypatch.setattr(scanner, "get", fake_get)

    try:
        findings, requests_made, pages_scanned = await scanner.scan(
            "https://example.com/"
        )

        assert requests_made == 0
        assert pages_scanned == 0

        assert len(findings) == 1
        assert findings[0].id == "target-request-error"
        assert findings[0].severity == Severity.HIGH

    finally:
        await scanner.close()


@pytest.mark.asyncio
async def test_scan_basic_http_target(monkeypatch):
    scanner = WebScanner(make_config())

    response = make_response()

    async def fake_get(url):
        return response

    monkeypatch.setattr(scanner, "get", fake_get)

    try:
        findings, requests_made, pages_scanned = await scanner.scan(
            "http://example.com/"
        )

        assert requests_made == 1
        assert pages_scanned == 1
        assert findings == []

    finally:
        await scanner.close()


@pytest.mark.asyncio
async def test_https_scan_invokes_tls(monkeypatch):
    scanner = WebScanner(make_config())

    response = make_response()

    async def fake_get(url):
        return response

    async def fake_tls(**kwargs):
        return [
            Finding(
                id="test-tls",
                title="Test TLS",
                severity=Severity.INFO,
                description="TLS test",
                url=f"https://{kwargs["hostname"]}/",
                category="tls",
            )
        ]

    monkeypatch.setattr(scanner, "get", fake_get)
    monkeypatch.setattr("app.scanner.check_tls", fake_tls)

    try:
        findings, requests_made, pages_scanned = await scanner.scan(
            "https://example.com/"
        )

        assert requests_made == 1
        assert pages_scanned == 1
        assert any(f.id == "test-tls" for f in findings)

    finally:
        await scanner.close()


@pytest.mark.asyncio
async def test_http_scan_does_not_invoke_tls(monkeypatch):
    scanner = WebScanner(make_config())

    response = make_response(
        url="http://example.com/"
    )

    async def fake_get(url):
        return response

    async def fake_tls(**kwargs):
        raise AssertionError("TLS must not run for HTTP")

    monkeypatch.setattr(scanner, "get", fake_get)
    monkeypatch.setattr("app.scanner.check_tls", fake_tls)

    try:
        findings, requests_made, pages_scanned = await scanner.scan(
            "http://example.com/"
        )

        assert requests_made == 1
        assert pages_scanned == 1
        assert findings == []

    finally:
        await scanner.close()


def test_checker_error():
    error = RuntimeError("boom")

    finding = WebScanner.checker_error(
        "headers",
        "https://example.com/",
        error,
    )

    assert finding.id == "checker-error-headers"
    assert finding.severity == Severity.INFO
    assert "RuntimeError" in finding.evidence
    assert "boom" in finding.evidence


def test_deduplicate_findings():
    finding1 = Finding(
        id="duplicate",
        title="Duplicate",
        severity=Severity.INFO,
        description="test",
        evidence="same",
        url="https://example.com/",
        category="test",
    )

    finding2 = Finding(
        id="duplicate",
        title="Duplicate",
        severity=Severity.INFO,
        description="test",
        evidence="same",
        url="https://example.com/",
        category="test",
    )

    finding3 = Finding(
        id="different",
        title="Different",
        severity=Severity.INFO,
        description="test",
        evidence="other",
        url="https://example.com/",
        category="test",
    )

    result = WebScanner.deduplicate(
        [finding1, finding2, finding3]
    )

    assert len(result) == 2
    assert {finding.id for finding in result} == {
        "duplicate",
        "different",
    }


def test_deduplicate_keeps_different_evidence():
    finding1 = Finding(
        id="same-id",
        title="Test",
        severity=Severity.INFO,
        description="test",
        evidence="one",
        url="https://example.com/",
        category="test",
    )

    finding2 = Finding(
        id="same-id",
        title="Test",
        severity=Severity.INFO,
        description="test",
        evidence="two",
        url="https://example.com/",
        category="test",
    )

    result = WebScanner.deduplicate(
        [finding1, finding2]
    )

    assert len(result) == 2
