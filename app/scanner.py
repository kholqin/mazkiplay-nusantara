from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx

from .config import AppConfig
from .models import ScanResult, ScanTarget


class ScannerError(Exception):
    """Base exception for scanner errors."""


class WebScanner:
    """
    Core HTTP scanning engine.

    The scanner is intentionally rate-limited and designed for
    authorized security assessments.
    """

    def __init__(self, config: AppConfig) -> None:
        self.config = config

        self.client = httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=config.scanner.max_redirects,
            timeout=config.scanner.timeout,
            headers={
                "User-Agent": config.scanner.user_agent,
                "Accept": "*/*",
            },
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        """
        Perform a rate-limited HTTP request.
        """

        response = await self.client.request(
            method=method,
            url=url,
            **kwargs,
        )

        delay = self.config.scanner.delay_between_requests

        if delay > 0:
            await asyncio.sleep(delay)

        return response

    async def get(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def scan_target(self, target: ScanTarget) -> ScanResult:
        """
        Initialize a scan result for a target.

        Actual check modules are executed by the orchestrator
        in later stages.
        """

        result = ScanResult(target=target)

        try:
            response = await self.get(str(target.url))

            result.requests_made += 1

            if response.is_error:
                result.findings.append(
                    {
                        "id": "http-status",
                        "title": "HTTP Error Response",
                        "severity": "INFO",
                        "description": (
                            f"Target returned HTTP "
                            f"status {response.status_code}."
                        ),
                        "url": str(response.url),
                        "category": "http",
                    }
                )

        except httpx.HTTPError as exc:
            raise ScannerError(
                f"Unable to reach target: {exc}"
            ) from exc

        finally:
            result.finish()

        return result


@asynccontextmanager
async def create_scanner(
    config: AppConfig,
) -> AsyncIterator[WebScanner]:
    """
    Async context manager for safe client lifecycle management.
    """

    scanner = WebScanner(config)

    try:
        yield scanner
    finally:
        await scanner.close()
