from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.models import Finding, Severity


def normalize_url(url: str) -> str:
    """Normalize a URL for crawl deduplication."""

    url, _ = urldefrag(url)
    parsed = urlparse(url)

    path = parsed.path or "/"

    return parsed._replace(
        path=path,
        fragment="",
    ).geturl()


def is_same_origin(
    base_url: str,
    candidate_url: str,
) -> bool:
    """Return True when candidate belongs to the same origin."""

    base = urlparse(base_url)
    candidate = urlparse(candidate_url)

    if candidate.scheme not in {"http", "https"}:
        return False

    return (
        candidate.scheme.lower() == base.scheme.lower()
        and candidate.hostname == base.hostname
        and candidate.port == base.port
    )


def extract_links(
    html: str,
    current_url: str,
) -> list[str]:
    """Extract normalized HTTP(S) links from an HTML document."""

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    discovered: list[str] = []
    seen: set[str] = set()

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")

        if not isinstance(href, str):
            continue

        href = href.strip()

        if not href:
            continue

        if href.startswith(
            (
                "#",
                "mailto:",
                "javascript:",
                "tel:",
                "data:",
            )
        ):
            continue

        absolute = urljoin(
            current_url,
            href,
        )

        parsed = urlparse(absolute)

        if parsed.scheme not in {"http", "https"}:
            continue

        normalized = normalize_url(absolute)

        if normalized not in seen:
            seen.add(normalized)
            discovered.append(normalized)

    return discovered


async def crawl(
    client: httpx.AsyncClient,
    start_url: str,
    max_pages: int = 100,
    request_delay: float = 0.0,
) -> tuple[list[str], list[Finding], int]:
    """
    Perform a bounded same-origin crawl.

    Returns:
        discovered pages,
        findings,
        number of HTTP requests initiated by the crawler.
    """

    max_pages = max(1, max_pages)
    request_delay = max(0.0, request_delay)

    start_url = normalize_url(start_url)

    queue: deque[str] = deque([start_url])
    queued: set[str] = {start_url}
    visited: set[str] = set()

    discovered: list[str] = []
    findings: list[Finding] = []

    requests_made = 0

    while queue and len(visited) < max_pages:
        current_url = queue.popleft()
        queued.discard(current_url)

        if current_url in visited:
            continue

        if not is_same_origin(
            start_url,
            current_url,
        ):
            continue

        visited.add(current_url)

        if request_delay > 0 and requests_made > 0:
            await asyncio.sleep(request_delay)

        try:
            response = await client.get(current_url)
            requests_made += 1

        except httpx.HTTPError as exc:
            requests_made += 1

            findings.append(
                Finding(
                    id="crawler-request-error",
                    title="Crawler Request Failed",
                    severity=Severity.INFO,
                    description=(
                        "A same-origin URL could not be retrieved "
                        "during crawling."
                    ),
                    evidence=f"{current_url}: {exc}",
                    url=current_url,
                    category="discovery",
                )
            )

            continue

        content_type = response.headers.get(
            "content-type",
            "",
        ).lower()

        if response.status_code >= 400:
            continue

        if "text/html" not in content_type:
            continue

        discovered.append(current_url)

        for link in extract_links(
            response.text,
            current_url,
        ):
            if not is_same_origin(
                start_url,
                link,
            ):
                continue

            if link in visited or link in queued:
                continue

            queue.append(link)
            queued.add(link)

    if discovered:
        findings.append(
            Finding(
                id="crawler-urls-discovered",
                title="Same-Origin URLs Discovered",
                severity=Severity.INFO,
                description=(
                    "The crawler discovered same-origin HTML URLs "
                    "within the configured page limit."
                ),
                evidence="\n".join(discovered[:50]),
                url=start_url,
                category="discovery",
                metadata={
                    "count": len(discovered),
                    "max_pages": max_pages,
                    "requests_made": requests_made,
                },
            )
        )

    if queue:
        findings.append(
            Finding(
                id="crawler-page-limit",
                title="Crawler Page Limit Reached",
                severity=Severity.INFO,
                description=(
                    "The crawler stopped because the configured "
                    "maximum page limit was reached."
                ),
                evidence=(
                    f"Visited: {len(visited)} / "
                    f"Maximum: {max_pages}"
                ),
                url=start_url,
                category="discovery",
                metadata={
                    "visited": len(visited),
                    "queued": len(queue),
                },
            )
        )

    return discovered, findings, requests_made
