from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx

from app.models import Finding, Severity


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    target = urlparse(candidate)

    return (
        target.scheme in {"http", "https"}
        and target.netloc == base.netloc
    )


async def check_robots(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[Finding]:
    """
    Passively inspect robots.txt.

    The scanner retrieves only robots.txt and does not crawl
    Disallow paths automatically.
    """

    findings: list[Finding] = []

    robots_url = urljoin(
        base_url.rstrip("/") + "/",
        "robots.txt",
    )

    try:
        response = await client.get(robots_url)
    except httpx.HTTPError as exc:
        findings.append(
            Finding(
                id="robots-request-error",
                title="robots.txt Request Failed",
                severity=Severity.INFO,
                description="The scanner could not retrieve robots.txt.",
                evidence=str(exc),
                recommendation=(
                    "Verify whether robots.txt is intentionally "
                    "unavailable."
                ),
                url=robots_url,
                category="discovery",
            )
        )
        return findings

    if response.status_code == 404:
        return findings

    if response.status_code >= 500:
        findings.append(
            Finding(
                id="robots-server-error",
                title="robots.txt Returned Server Error",
                severity=Severity.INFO,
                description=(
                    "robots.txt returned a server-side error response."
                ),
                evidence=f"HTTP {response.status_code}",
                url=robots_url,
                category="discovery",
            )
        )
        return findings

    if response.status_code >= 400:
        return findings

    disallowed: list[str] = []
    sitemaps: list[str] = []

    for raw_line in response.text.splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        directive, value = line.split(":", 1)

        directive = directive.strip().lower()
        value = value.strip()

        if directive == "disallow" and value:
            disallowed.append(value)

        elif directive == "sitemap" and value:
            sitemap_url = urljoin(
                robots_url,
                value,
            )

            if _same_origin(base_url, sitemap_url):
                sitemaps.append(sitemap_url)

    if disallowed:
        findings.append(
            Finding(
                id="robots-disallow-rules",
                title="robots.txt Contains Disallowed Paths",
                severity=Severity.INFO,
                description=(
                    "robots.txt exposes paths that search-engine "
                    "crawlers are instructed not to index."
                ),
                evidence="\n".join(disallowed[:50]),
                recommendation=(
                    "Do not rely on robots.txt as an access-control "
                    "mechanism. Verify that sensitive resources are "
                    "protected by server-side authorization."
                ),
                url=robots_url,
                category="discovery",
                metadata={
                    "count": len(disallowed),
                    "paths": disallowed[:50],
                },
            )
        )

    if sitemaps:
        findings.append(
            Finding(
                id="robots-sitemaps",
                title="Sitemap References Discovered",
                severity=Severity.INFO,
                description=(
                    "robots.txt references one or more sitemap resources."
                ),
                evidence="\n".join(sitemaps),
                recommendation=(
                    "Review sitemap contents to ensure sensitive or "
                    "non-public URLs are not unnecessarily exposed."
                ),
                url=robots_url,
                category="discovery",
                metadata={
                    "sitemaps": sitemaps,
                },
            )
        )

    return findings
