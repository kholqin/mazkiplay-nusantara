from __future__ import annotations

import asyncio
import socket

from .models import HostAsset, HostStatus
from .scope import Scope


DEFAULT_PREFIXES = [
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "login",
    "portal",
    "dev",
    "development",
    "test",
    "testing",
    "stage",
    "staging",
    "beta",
    "demo",
    "preview",
    "cdn",
    "static",
    "assets",
    "media",
    "mail",
    "smtp",
    "imap",
    "vpn",
    "remote",
    "docs",
    "documentation",
    "status",
]


def resolve_hostname(hostname: str) -> list[str]:
    addresses: set[str] = set()

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for result in results:
            address = result[4][0]
            addresses.add(address)

    except OSError:
        pass

    return sorted(addresses)


def generate_candidates(
    scope: Scope,
    prefixes: list[str] | None = None,
) -> list[str]:

    prefixes = prefixes or DEFAULT_PREFIXES

    candidates = {
        scope.hostname,
    }

    for prefix in prefixes:
        prefix = prefix.strip().lower()

        if not prefix:
            continue

        hostname = f"{prefix}.{scope.hostname}"

        if scope.contains(hostname):
            candidates.add(hostname)

    return sorted(candidates)


async def probe_host(
    hostname: str,
    timeout: float = 2.5,
) -> HostAsset:

    ips = resolve_hostname(hostname)

    if not ips:
        return HostAsset(
            hostname=hostname,
            ips=[],
            status=HostStatus.DEAD,
        )

    http_status = None
    https_status = None

    try:
        import httpx

        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
        ) as client:

            try:
                response = await client.get(
                    f"https://{hostname}/"
                )
                https_status = response.status_code

            except httpx.HTTPError:
                pass

            if https_status is None:

                try:
                    response = await client.get(
                        f"http://{hostname}/"
                    )
                    http_status = response.status_code

                except httpx.HTTPError:
                    pass

    except Exception:
        pass

    status = (
        HostStatus.LIVE
        if (
            http_status is not None
            or https_status is not None
        )
        else HostStatus.UNKNOWN
    )

    return HostAsset(
        hostname=hostname,
        ips=ips,
        status=status,
        http_status=http_status,
        https_status=https_status,
    )


async def discover_subdomains(
    scope: Scope,
    prefixes: list[str] | None = None,
    concurrency: int = 10,
) -> list[HostAsset]:

    candidates = generate_candidates(
        scope,
        prefixes,
    )

    semaphore = asyncio.Semaphore(
        max(1, concurrency)
    )

    async def worker(hostname: str) -> HostAsset:
        async with semaphore:
            return await probe_host(hostname)

    results = await asyncio.gather(
        *(worker(host) for host in candidates)
    )

    return sorted(
        results,
        key=lambda item: item.hostname,
    )
