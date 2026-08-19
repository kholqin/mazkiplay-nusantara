import httpx
import pytest

from modules.robots import _same_origin, check_robots


class FakeAsyncClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.requested_url = None

    async def get(self, url):
        self.requested_url = url

        if self.error is not None:
            raise self.error

        return self.response


def make_response(
    status_code: int = 200,
    text: str = "",
) -> httpx.Response:
    return httpx.Response(
        status_code,
        text=text,
        request=httpx.Request(
            "GET",
            "https://example.com/robots.txt",
        ),
    )


def test_same_origin():
    assert _same_origin(
        "https://example.com/",
        "https://example.com/sitemap.xml",
    )

    assert _same_origin(
        "http://example.com/",
        "http://example.com/sitemap.xml",
    )


def test_different_origin():
    assert not _same_origin(
        "https://example.com/",
        "https://evil.example/sitemap.xml",
    )


def test_invalid_scheme_is_not_same_origin():
    assert not _same_origin(
        "https://example.com/",
        "ftp://example.com/file",
    )


@pytest.mark.asyncio
async def test_robots_404_returns_no_findings():
    client = FakeAsyncClient(
        response=make_response(404)
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert findings == []
    assert client.requested_url == (
        "https://example.com/robots.txt"
    )


@pytest.mark.asyncio
async def test_robots_server_error():
    client = FakeAsyncClient(
        response=make_response(500)
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "robots-server-error" in ids


@pytest.mark.asyncio
async def test_robots_other_client_error_is_ignored():
    client = FakeAsyncClient(
        response=make_response(403)
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert findings == []


@pytest.mark.asyncio
async def test_robots_request_error():
    error = httpx.ConnectError(
        "simulated connection failure"
    )

    client = FakeAsyncClient(
        error=error
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id == "robots-request-error"
    assert finding.category == "discovery"
    assert "simulated connection failure" in finding.evidence


@pytest.mark.asyncio
async def test_disallow_rules_are_reported():
    robots = """
# comment

User-agent: *
Disallow: /admin
Disallow: /private
Allow: /
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    finding = next(
        item
        for item in findings
        if item.id == "robots-disallow-rules"
    )

    assert finding.metadata["count"] == 2
    assert finding.metadata["paths"] == [
        "/admin",
        "/private",
    ]

    assert "/admin" in finding.evidence
    assert "/private" in finding.evidence


@pytest.mark.asyncio
async def test_same_origin_sitemap_is_reported():
    robots = """
User-agent: *
Disallow: /admin

Sitemap: https://example.com/sitemap.xml
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    ids = {finding.id for finding in findings}

    assert "robots-disallow-rules" in ids
    assert "robots-sitemaps" in ids

    sitemap_finding = next(
        item
        for item in findings
        if item.id == "robots-sitemaps"
    )

    assert sitemap_finding.metadata["sitemaps"] == [
        "https://example.com/sitemap.xml"
    ]


@pytest.mark.asyncio
async def test_relative_sitemap_is_resolved():
    robots = """
User-agent: *
Sitemap: /sitemap.xml
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    sitemap_finding = next(
        item
        for item in findings
        if item.id == "robots-sitemaps"
    )

    assert sitemap_finding.metadata["sitemaps"] == [
        "https://example.com/sitemap.xml"
    ]


@pytest.mark.asyncio
async def test_external_sitemap_is_ignored():
    robots = """
User-agent: *
Sitemap: https://other.example/sitemap.xml
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert "robots-sitemaps" not in {
        finding.id for finding in findings
    }


@pytest.mark.asyncio
async def test_empty_and_malformed_lines_are_ignored():
    robots = """
# comment

User-agent: *
this is not a directive
Disallow
: invalid
Allow: /
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert findings == []


@pytest.mark.asyncio
async def test_empty_disallow_value_is_ignored():
    robots = """
User-agent: *
Disallow:
Sitemap:
"""

    client = FakeAsyncClient(
        response=make_response(
            200,
            robots,
        )
    )

    findings = await check_robots(
        client,
        "https://example.com/",
    )

    assert findings == []
