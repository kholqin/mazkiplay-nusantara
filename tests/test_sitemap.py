import pytest
import httpx

from modules.sitemap import (
    _deduplicate,
    _same_origin,
    _strip_namespace,
    check_sitemap,
    parse_sitemap,
)


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
    content: str = "",
    status_code: int = 200,
) -> httpx.Response:
    return httpx.Response(
        status_code,
        text=content,
        request=httpx.Request(
            "GET",
            "https://example.com/sitemap.xml",
        ),
    )


def test_same_origin():
    assert _same_origin(
        "https://example.com/",
        "https://example.com/a",
    )

    assert not _same_origin(
        "https://example.com/",
        "https://other.example/a",
    )

    assert not _same_origin(
        "https://example.com/",
        "ftp://example.com/file",
    )


def test_strip_namespace():
    assert _strip_namespace(
        "{http://www.sitemaps.org/schemas/sitemap/0.9}url"
    ) == "url"

    assert _strip_namespace("LOC") == "loc"


def test_parse_urlset_same_origin_only():
    content = """
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url><loc>https://example.com/one</loc></url>
        <url><loc>/two</loc></url>
        <url><loc>https://other.example/three</loc></url>
    </urlset>
    """


    pages, nested = parse_sitemap(
        content,
        "https://example.com/",
    )

    assert pages == [
        "https://example.com/one",
        "https://example.com/two",
    ]
    assert nested == []


def test_parse_sitemapindex_same_origin_only():
    content = """
    <sitemapindex
        xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <sitemap>
            <loc>https://example.com/sitemap-a.xml</loc>
        </sitemap>
        <sitemap>
            <loc>/sitemap-b.xml</loc>
        </sitemap>
        <sitemap>
            <loc>https://other.example/sitemap-c.xml</loc>
        </sitemap>
    </sitemapindex>
    """

    pages, nested = parse_sitemap(
        content,
        "https://example.com/",
    )

    assert pages == []
    assert nested == [
        "https://example.com/sitemap-a.xml",
        "https://example.com/sitemap-b.xml",
    ]


def test_parse_invalid_xml_returns_empty():
    pages, nested = parse_sitemap(
        "<not-valid-xml",
        "https://example.com/",
    )

    assert pages == []
    assert nested == []


def test_parse_ignores_empty_loc_and_unknown_root():
    content = """
    <root>
        <loc></loc>
        <item>ignored</item>
    </root>
    """

    pages, nested = parse_sitemap(
        content,
        "https://example.com/",
    )

    assert pages == []
    assert nested == []


def test_parse_deduplicates_urls():
    content = """
    <urlset>
        <url><loc>/same</loc></url>
        <url><loc>/same</loc></url>
        <url><loc>/other</loc></url>
    </urlset>
    """

    pages, nested = parse_sitemap(
        content,
        "https://example.com/",
    )

    assert pages == [
        "https://example.com/same",
        "https://example.com/other",
    ]
    assert nested == []


@pytest.mark.asyncio
async def test_check_sitemap_404_returns_empty():
    client = FakeAsyncClient(
        response=make_response(status_code=404)
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
    )

    assert urls == []
    assert findings == []
    assert client.requested_url == "https://example.com/sitemap.xml"


@pytest.mark.asyncio
async def test_check_sitemap_request_error():
    client = FakeAsyncClient(
        error=httpx.ConnectError("connection failed")
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
    )

    assert urls == []
    assert len(findings) == 1
    assert findings[0].id == "sitemap-request-error"


@pytest.mark.asyncio
async def test_check_sitemap_http_error():
    client = FakeAsyncClient(
        response=make_response(status_code=500)
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
    )

    assert urls == []
    assert len(findings) == 1
    assert findings[0].id == "sitemap-http-error"


@pytest.mark.asyncio
async def test_check_sitemap_discovers_urls():
    content = """
    <urlset>
        <url><loc>https://example.com/a</loc></url>
        <url><loc>https://example.com/b</loc></url>
        <url><loc>https://other.example/c</loc></url>
    </urlset>
    """

    client = FakeAsyncClient(
        response=make_response(content)
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
        max_urls=100,
    )

    assert urls == [
        "https://example.com/a",
        "https://example.com/b",
    ]

    ids = {finding.id for finding in findings}

    assert "sitemap-urls-discovered" in ids
    assert "nested-sitemaps-discovered" not in ids


@pytest.mark.asyncio
async def test_check_sitemap_discovers_nested_sitemaps():
    content = """
    <sitemapindex>
        <sitemap>
            <loc>https://example.com/products.xml</loc>
        </sitemap>
        <sitemap>
            <loc>https://example.com/news.xml</loc>
        </sitemap>
    </sitemapindex>
    """

    client = FakeAsyncClient(
        response=make_response(content)
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
    )

    assert urls == []

    ids = {finding.id for finding in findings}

    assert "nested-sitemaps-discovered" in ids
    assert "sitemap-urls-discovered" not in ids


@pytest.mark.asyncio
async def test_check_sitemap_respects_max_urls():
    content = """
    <urlset>
        <url><loc>/1</loc></url>
        <url><loc>/2</loc></url>
        <url><loc>/3</loc></url>
    </urlset>
    """

    client = FakeAsyncClient(
        response=make_response(content)
    )

    urls, findings = await check_sitemap(
        client,
        "https://example.com/",
        max_urls=2,
    )

    assert urls == [
        "https://example.com/1",
        "https://example.com/2",
    ]

    assert "sitemap-urls-discovered" in {
        finding.id for finding in findings
    }


def test_deduplicate_preserves_order():
    assert _deduplicate(
        ["a", "b", "a", "c", "b"]
    ) == ["a", "b", "c"]
