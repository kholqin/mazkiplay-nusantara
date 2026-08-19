import httpx
import pytest

from modules.crawler import normalize_url, extract_links, crawl


def test_normalize_url_removes_fragment():
    assert normalize_url(
        "https://example.com/test#fragment"
    ) == "https://example.com/test"


def test_extract_links_filters_and_deduplicates():
    html = """
    <a href="/one">one</a>
    <a href="/two#section">two</a>
    <a href="mailto:test@example.com">mail</a>
    <a href="javascript:void(0)">js</a>
    <a href="/one">duplicate</a>
    """

    links = extract_links(
        html,
        "https://example.com/",
    )

    assert links == [
        "https://example.com/one",
        "https://example.com/two",
    ]


@pytest.mark.asyncio
async def test_crawl_returns_request_count():
    routes = {
        "https://example.com/": "<a href='/one'>one</a>",
        "https://example.com/one": "<html>one</html>",
    }

    async def handler(request):
        body = routes.get(
            str(request.url),
            "<html>not found</html>",
        )

        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=body,
            request=request,
        )

    transport = httpx.MockTransport(handler)

    async with httpx.AsyncClient(transport=transport) as client:
        pages, findings, requests_made = await crawl(
            client=client,
            start_url="https://example.com/",
            max_pages=10,
        )

    assert pages == [
        "https://example.com/",
        "https://example.com/one",
    ]
    assert requests_made == 2
    assert any(
        finding.id == "crawler-urls-discovered"
        for finding in findings
    )
