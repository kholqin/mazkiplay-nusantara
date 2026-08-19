from __future__ import annotations

from datetime import datetime, timezone

import httpx

from .assets import extract_assets
from .dns import collect_dns_profile
from .fingerprint import fingerprint_http
from .evidence import collect_http_evidence
from .analysis import (
    analyze_evidence,
    analyze_missing_security_headers,
)
from .http import observe
from .models import SentinelResult
from .scope import Scope
from .subdomains import discover_subdomains, probe_host


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


async def run_sentinel(
    target: str,
    *,
    allow_subdomains: bool = True,
    discover: bool = True,
    observe_http: bool = True,
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

    # ========================================================
    # DNS
    # ========================================================

    result.dns = collect_dns_profile(
        scope.hostname
    )

    # ========================================================
    # HOST DISCOVERY
    # ========================================================

    if discover:
        result.hosts = await discover_subdomains(
            scope
        )

    # Root host must always exist.
    if not any(
        host.hostname == scope.hostname
        for host in result.hosts
    ):
        root_host = await probe_host(
            scope.hostname
        )

        result.hosts.insert(
            0,
            root_host,
        )

    result.hosts_discovered = len(
        result.hosts
    )

    # ========================================================
    # HTTP OBSERVATION
    # ========================================================

    if observe_http:

        headers = {
            "User-Agent": (
                "Mazkiplay-Nusantara-Sentinel/0.2"
            ),
            "Accept": (
                "text/html,"
                "application/xhtml+xml,"
                "application/json;q=0.9,"
                "*/*;q=0.8"
            ),
        }

        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=True,
            headers=headers,
            timeout=10.0,
        ) as client:

            root_url = (
                f"{scope.scheme}://"
                f"{scope.hostname}/"
            )

            observation = await observe(
                client,
                root_url,
            )

            result.http_observations.append(
                observation
            )

            result.requests += 1

            # =================================================
            # FINGERPRINT
            # =================================================

            fingerprint = fingerprint_http(
                observation
            )

            result.fingerprints.append(
                fingerprint
            )

            # =================================================
            # EVIDENCE
            # =================================================

            http_evidence = collect_http_evidence(
                observation
            )

            result.evidence.extend(
                http_evidence
            )

            # =================================================
            # ANALYSIS
            # =================================================

            findings = analyze_evidence(
                http_evidence
            )

            result.findings.extend(
                findings
            )

            missing_header_findings = (
                analyze_missing_security_headers(
                    observation
                )
            )

            result.findings.extend(
                missing_header_findings
            )

            # =================================================
            # HTML ASSETS
            # =================================================

            if (
                observation.error is None
                and observation.status_code is not None
                and observation.content_type
                and "text/html"
                in observation.content_type.lower()
            ):

                try:
                    response = await client.get(
                        observation.final_url
                        or observation.url
                    )

                    result.requests += 1

                    html = response.text

                    assets = extract_assets(
                        html,
                        (
                            observation.final_url
                            or observation.url
                        ),
                        scope,
                    )

                    result.assets.extend(
                        assets
                    )

                    result.pages += 1

                except httpx.HTTPError:
                    pass

    # ========================================================
    # STATISTICS
    # ========================================================

    result.assets_discovered = len(
        result.assets
    )

    result.finished_at = utc_now()

    return result
