from __future__ import annotations

from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from app.models import Finding, Severity


def normalize_url(url: str) -> str:
    """
    Normalize a URL for crawl deduplication.
    """

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
    """
    Return True when candidate belongs to the same origin.
    """

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
    """
    Extract and normalize links from an HTML document.
    """

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    discovered: list[str] = []

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href")

        if not href:
            continue

        href = href.strip()

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

        normalized = normalize_url(absolute)

        if normalized not in discovered:
            discovered.append(normalized)

    return discovered


async def crawl(
    client: httpx.AsyncClient,
    start_url: str,
    max_pages: int = 100,
) -> tuple[list[str], list[Finding]]:
    """
    Perform a bounded same-origin crawl.

    Only GET requests to same-origin URLs are made.
    """

    queue: deque[str] = deque(
        [normalize_url(start_url)]
    )

    visited: set[str] = set()
    discovered: list[str] = []
    findings: list[Finding] = []

    while queue and len(visited) < max_pages:
        current_url = queue.popleft()

        if current_url in visited:
            continue

        if not is_same_origin(
            start_url,
            current_url,
        ):
            continue

        visited.add(current_url)

        try:
            response = await client.get(
                current_url
            )
        except httpx.HTTPError as exc:
            findings.append(
                Finding(
                    id="crawler-request-error",
                    title="Crawler Request Failed",
                    severity=Severity.INFO,
                    description=(
                        "A same-origin URL could not be retrieved "
                        "during crawling."
                    ),
                    evidence=(
                        f"{current_url}: {exc}"
                    ),
                    url=current_url,
                    category="discovery",
                )
            )
            continue

        content_type = response.headers.get(
            "content-type",
            "",
        ).lower()

        if (
            response.status_code >= 400
            or "text/html" not in content_type
        ):
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

            if link not in visited:
                queue.append(link)

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
                evidence="\n".join(
                    discovered[:50]
                ),
                url=start_url,
                category="discovery",
                metadata={
                    "count": len(discovered),
                    "max_pages": max_pages,
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
            )
        )

    return discovered, findings
