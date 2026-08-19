from __future__ import annotations

from datetime import datetime, timezone

from .dns import collect_dns_profile
from .models import SentinelResult
from .scope import Scope
from .subdomains import discover_subdomains


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
    )


async def run_sentinel(
    target: str,
    *,
    allow_subdomains: bool = True,
    discover: bool = True,
) -> SentinelResult:

    started_at = utc_now()

    scope = Scope(
        target,
        allow_subdomains=allow_subdomains,
    )

    result = SentinelResult(
        target=scope.target,
        started_at=started_at,
    )

    # --------------------------------------------------
    # DNS
    # --------------------------------------------------

    result.dns = collect_dns_profile(
        scope.hostname
    )

    # --------------------------------------------------
    # Host / subdomain discovery
    # --------------------------------------------------

    if discover:

        result.hosts = (
            await discover_subdomains(
                scope
            )
        )

    # Root host should always be represented.
    if not any(
        host.hostname == scope.hostname
        for host in result.hosts
    ):
        from .subdomains import probe_host

        root_host = await probe_host(
            scope.hostname
        )

        result.hosts.insert(
            0,
            root_host,
        )

    result.finished_at = utc_now()

    return result
