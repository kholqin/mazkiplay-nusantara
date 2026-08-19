from __future__ import annotations

from urllib.parse import urlparse

import httpx

from app.config import ScannerConfig
from app.models import Finding, Severity

from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.csp import check_csp
from modules.crawler import crawl
from modules.disclosure import check_disclosure
from modules.headers import run_header_checks
from modules.redirects import check_redirect_chain
from modules.robots import check_robots
from modules.sitemap import check_sitemap
from modules.tls import check_tls


class WebScanner:
    """
    Main passive security assessment engine.

    The scanner coordinates individual modules and keeps
    transport/orchestration logic in one place.
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

        timeout = httpx.Timeout(
            timeout=config.timeout,
            connect=config.connect_timeout,
            read=config.read_timeout,
            write=config.write_timeout,
            pool=config.pool_timeout,
        )

        limits = httpx.Limits(
            max_connections=config.concurrency,
            max_keepalive_connections=config.concurrency,
        )

        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=config.follow_redirects,
            max_redirects=config.max_redirects,
            verify=config.verify_tls,
            limits=limits,
            headers={
                "User-Agent": config.user_agent,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.9,*/*;q=0.8"
                ),
            },
        )

    async def get(self, url: str) -> httpx.Response:
        """Perform one normal HTTP GET request."""
        return await self.client.get(url)

    async def analyze_response(
        self,
        response: httpx.Response,
        original_url: str,
    ) -> list[Finding]:
        """Run enabled passive response checkers."""

        checks = []

        if self.config.enable_headers:
            checks.append(
                ("headers", lambda: run_header_checks(response))
            )

        if self.config.enable_cookies:
            checks.append(
                ("cookies", lambda: check_cookies(response))
            )

        if self.config.enable_cors:
            checks.append(
                ("cors", lambda: check_cors(response))
            )

        if self.config.enable_csp:
            checks.append(
                ("csp", lambda: check_csp(response))
            )

        if self.config.enable_disclosure:
            checks.append(
                ("disclosure", lambda: check_disclosure(response))
            )

        if self.config.enable_redirects:
            checks.append(
                (
                    "redirects",
                    lambda: check_redirect_chain(
                        response,
                        original_url,
                    ),
                )
            )

        findings: list[Finding] = []

        for name, checker in checks:
            try:
                findings.extend(checker())
            except Exception as exc:
                findings.append(
                    self.checker_error(
                        name,
                        response.url,
                        exc,
                    )
                )

        return self.deduplicate(findings)

    async def scan(
        self,
        url: str,
    ) -> tuple[list[Finding], int, int]:
        """
        Run the complete assessment.

        Returns:
            findings:
                Security findings produced by the assessment.
            requests_made:
                Number of HTTP requests initiated by the scanner.
            pages_scanned:
                Number of HTML pages successfully processed.
        """

        target = str(url).strip()
        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"}:
            return [
                Finding(
                    id="invalid-target-scheme",
                    title="Unsupported Target Scheme",
                    severity=Severity.INFO,
                    description=(
                        "Only HTTP and HTTPS targets are supported."
                    ),
                    evidence=target,
                    recommendation=(
                        "Use an http:// or https:// target."
                    ),
                    url=None,
                    category="scanner",
                )
            ], 0, 0

        findings: list[Finding] = []
        requests_made = 0
        pages_scanned = 0
        scanned_pages: set[str] = set()

        # --------------------------------------------------
        # Primary request
        # --------------------------------------------------

        try:
            response = await self.get(target)
            requests_made += 1
            scanned_pages.add(target)
            pages_scanned = len(scanned_pages)

        except httpx.HTTPError as exc:
            findings.append(
                Finding(
                    id="target-request-error",
                    title="Target Request Failed",
                    severity=Severity.HIGH,
                    description=(
                        "The target could not be retrieved."
                    ),
                    evidence=str(exc),
                    recommendation=(
                        "Check connectivity, target availability, "
                        "TLS configuration, and scanner settings."
                    ),
                    url=target,
                    category="scanner",
                )
            )

            return (
                self.deduplicate(findings),
                requests_made,
                pages_scanned,
            )

        # --------------------------------------------------
        # Response checks
        # --------------------------------------------------

        findings.extend(
            await self.analyze_response(
                response,
                target,
            )
        )

        # --------------------------------------------------
        # robots.txt
        # --------------------------------------------------

        if self.config.enable_robots:
            try:
                findings.extend(
                    await check_robots(
                        self.client,
                        target,
                    )
                )
                requests_made += 1
            except Exception as exc:
                findings.append(
                    self.checker_error(
                        "robots",
                        target,
                        exc,
                    )
                )

        # --------------------------------------------------
        # sitemap.xml
        # --------------------------------------------------

        if self.config.enable_sitemap:
            try:
                _, sitemap_findings = await check_sitemap(
                    self.client,
                    target,
                    max_urls=self.config.max_sitemap_urls,
                )

                findings.extend(sitemap_findings)
                requests_made += 1

            except Exception as exc:
                findings.append(
                    self.checker_error(
                        "sitemap",
                        target,
                        exc,
                    )
                )

        # --------------------------------------------------
        # Same-origin crawler
        # --------------------------------------------------

        if self.config.enable_crawler:
            try:
                (
                    crawler_pages,
                    crawler_findings,
                    crawler_requests,
                ) = await crawl(
                    client=self.client,
                    start_url=target,
                    max_pages=self.config.max_pages,
                    request_delay=self.config.request_delay,
                )

                findings.extend(crawler_findings)
                requests_made += crawler_requests
                scanned_pages.update(crawler_pages)
                pages_scanned = len(scanned_pages)

            except Exception as exc:
                findings.append(
                    self.checker_error(
                        "crawler",
                        target,
                        exc,
                    )
                )

        # --------------------------------------------------
        # TLS certificate
        # --------------------------------------------------

        if parsed.scheme == "https":
            try:
                findings.extend(
                    await check_tls(
                        hostname=parsed.hostname,
                        port=parsed.port or 443,
                        timeout=self.config.timeout,
                    )
                )
            except Exception as exc:
                findings.append(
                    self.checker_error(
                        "tls",
                        target,
                        exc,
                    )
                )

        return (
                self.deduplicate(findings),
                requests_made,
                pages_scanned,
            )

    async def close(self) -> None:
        """Close the HTTP client."""

        await self.client.aclose()

    @staticmethod
    def checker_error(
        name: str,
        url: object,
        error: Exception,
    ) -> Finding:
        """Convert checker failures into INFO findings."""

        return Finding(
            id=f"checker-error-{name}",
            title=f"{name} Checker Error",
            severity=Severity.INFO,
            description=(
                "The checker failed, but the remaining "
                "assessment continued."
            ),
            evidence=(
                f"{type(error).__name__}: {error}"
            ),
            recommendation=(
                "Review the checker implementation and "
                "the target response."
            ),
            url=str(url),
            category="scanner",
        )

    @staticmethod
    def deduplicate(
        findings: list[Finding],
    ) -> list[Finding]:
        """Remove duplicate findings."""

        unique: dict[
            tuple[str, str, str],
            Finding,
        ] = {}

        for finding in findings:
            key = (
                finding.id,
                str(finding.url),
                finding.evidence or "",
            )

            unique[key] = finding

        return list(unique.values())

