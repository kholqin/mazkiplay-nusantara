from __future__ import annotations

from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import httpx

from app.models import Finding, Severity


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(candidate)

    return (
        target.scheme in {"http", "https"}
        and target.netloc == base.netloc
    )


def _strip_namespace(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_sitemap(
    content: str,
    base_url: str,
) -> tuple[list[str], list[str]]:
    """
    Parse sitemap XML.

    Returns:
        (page_urls, nested_sitemaps)
    """

    page_urls: list[str] = []
    nested_sitemaps: list[str] = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return page_urls, nested_sitemaps

    root_type = _strip_namespace(root.tag)

    if root_type == "urlset":
        for element in root.iter():
            if _strip_namespace(element.tag) != "loc":
                continue

            if not element.text:
                continue

            candidate = urljoin(
                base_url,
                element.text.strip(),
            )

            if _same_origin(base_url, candidate):
                page_urls.append(candidate)

    elif root_type == "sitemapindex":
        for element in root.iter():
            if _strip_namespace(element.tag) != "loc":
                continue

            if not element.text:
                continue

            candidate = urljoin(
                base_url,
                element.text.strip(),
            )

            if _same_origin(base_url, candidate):
                nested_sitemaps.append(candidate)

    return (
        _deduplicate(page_urls),
        _deduplicate(nested_sitemaps),
    )


async def check_sitemap(
    client: httpx.AsyncClient,
    base_url: str,
    max_urls: int = 100,
) -> tuple[list[str], list[Finding]]:
    """
    Retrieve and inspect the site's sitemap.xml.

    Only same-origin URLs are returned.
    """

    findings: list[Finding] = []
    discovered_urls: list[str] = []

    sitemap_url = urljoin(
        base_url.rstrip("/") + "/",
        "sitemap.xml",
    )

    try:
        response = await client.get(sitemap_url)
    except httpx.HTTPError as exc:
        findings.append(
            Finding(
                id="sitemap-request-error",
                title="Sitemap Request Failed",
                severity=Severity.INFO,
                description=(
                    "The scanner could not retrieve sitemap.xml."
                ),
                evidence=str(exc),
                url=sitemap_url,
                category="discovery",
            )
        )

        return discovered_urls, findings

    if response.status_code == 404:
        return discovered_urls, findings

    if response.status_code >= 400:
        findings.append(
            Finding(
                id="sitemap-http-error",
                title="Sitemap Returned HTTP Error",
                severity=Severity.INFO,
                description=(
                    "The sitemap endpoint returned an error response."
                ),
                evidence=f"HTTP {response.status_code}",
                url=sitemap_url,
                category="discovery",
            )
        )

        return discovered_urls, findings

    pages, nested_sitemaps = parse_sitemap(
        response.text,
        base_url,
    )

    discovered_urls.extend(pages[:max_urls])

    if nested_sitemaps:
        findings.append(
            Finding(
                id="nested-sitemaps-discovered",
                title="Nested Sitemaps Discovered",
                severity=Severity.INFO,
                description=(
                    "The sitemap index references additional "
                    "same-origin sitemap files."
                ),
                evidence="\n".join(
                    nested_sitemaps[:25]
                ),
                url=sitemap_url,
                category="discovery",
                metadata={
                    "count": len(nested_sitemaps),
                    "sitemaps": nested_sitemaps[:25],
                },
            )
        )

    if discovered_urls:
        findings.append(
            Finding(
                id="sitemap-urls-discovered",
                title="URLs Discovered From Sitemap",
                severity=Severity.INFO,
                description=(
                    "The sitemap exposed same-origin URLs that can "
                    "be considered for subsequent authorized scanning."
                ),
                evidence="\n".join(
                    discovered_urls[:50]
                ),
                url=sitemap_url,
                category="discovery",
                metadata={
                    "count": len(discovered_urls),
                },
            )
        )

    return discovered_urls, findings


def _deduplicate(
    values: list[str],
) -> list[str]:
    return list(dict.fromkeys(values))
