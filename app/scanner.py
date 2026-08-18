from __future__ import annotations

from typing import Any

import httpx

from app.config import ScannerConfig
from app.models import Finding

from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.csp import check_csp
from modules.disclosure import check_disclosure
from modules.headers import run_header_checks
from modules.redirects import check_redirect_chain


class WebScanner:
    """
    Central orchestration engine for Mazkiplay Nusantara.

    The engine performs bounded HTTP security assessment and delegates
    individual checks to dedicated modules.
    """

    def __init__(
        self,
        config: ScannerConfig,
    ) -> None:

        self.config = config

        self.client = httpx.AsyncClient(
            timeout=config.timeout,
            follow_redirects=config.follow_redirects,
            headers={
                "User-Agent": config.user_agent,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/json;q=0.9,*/*;q=0.8"
                ),
            },
        )

    async def get(
        self,
        url: str,
    ) -> httpx.Response:
        """
        Perform a normal GET request.
        """

        response = await self.client.get(
            url
        )

        return response

    async def analyze_response(
        self,
        response: httpx.Response,
        original_url: str,
    ) -> list[Finding]:
        """
        Execute all passive response-level checkers.
        """

        findings: list[Finding] = []

        checkers = (
            (
                "headers",
                lambda: run_header_checks(
                    response
                ),
            ),
            (
                "cookies",
                lambda: check_cookies(
                    response
                ),
            ),
            (
                "cors",
                lambda: check_cors(
                    response
                ),
            ),
            (
                "csp",
                lambda: check_csp(
                    response
                ),
            ),
            (
                "disclosure",
                lambda: check_disclosure(
                    response
                ),
            ),
            (
                "redirects",
                lambda: check_redirect_chain(
                    response,
                    original_url,
                ),
            ),
        )

        for name, checker in checkers:

            try:

                results = checker()

                findings.extend(
                    results
                )

            except Exception as exc:

                findings.append(
                    self._checker_error(
                        name,
                        response.url,
                        exc,
                    )
                )

        return self._deduplicate(
            findings
        )

    async def scan(
        self,
        url: str,
    ) -> tuple[list[Finding], int]:
        """
        Run the central passive assessment engine.

        Returns:
            findings, request_count
        """

        request_count = 0

        response = await self.get(
            url
        )

        request_count += 1

        findings = await self.analyze_response(
            response=response,
            original_url=url,
        )

        return (
            findings,
            request_count,
        )

    async def close(self) -> None:
        """
        Close the HTTP client.
        """

        await self.client.aclose()

    @staticmethod
    def _checker_error(
        checker_name: str,
        url: Any,
        error: Exception,
    ) -> Finding:
        """
        Convert checker exceptions into INFO findings instead
        of crashing the entire scan.
        """

        return Finding(
            id=f"checker-error-{checker_name}",
            title=f"{checker_name} Checker Error",
            severity="INFO",
            description=(
                "A security checker could not complete. "
                "The remaining checks continued normally."
            ),
            evidence=str(error),
            recommendation=(
                "Review the checker implementation or target "
                "response that caused the exception."
            ),
            url=str(url),
            category="scanner",
        )

    @staticmethod
    def _deduplicate(
        findings: list[Finding],
    ) -> list[Finding]:
        """
        Remove duplicate findings.
        """

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

        return list(
            unique.values()
        )
