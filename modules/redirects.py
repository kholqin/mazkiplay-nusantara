from __future__ import annotations

from urllib.parse import urlparse

import httpx

from app.models import Finding, Severity


REDIRECT_CODES = {
    301,
    302,
    303,
    307,
    308,
}


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)

    return (
        parsed.scheme.lower(),
        parsed.hostname.lower() if parsed.hostname else "",
        parsed.port,
    )


def check_redirect_chain(
    response: httpx.Response,
    original_url: str,
) -> list[Finding]:
    """
    Analyze the redirect history already observed by httpx.
    """

    findings: list[Finding] = []

    history = response.history

    if not history:
        return findings

    redirect_count = len(history)

    if redirect_count > 3:
        findings.append(
            Finding(
                id="long-redirect-chain",
                title="Long Redirect Chain",
                severity=Severity.LOW,
                description=(
                    f"The target produced {redirect_count} redirects "
                    "before reaching the final response."
                ),
                evidence="\n".join(
                    f"{item.status_code} {item.url}"
                    for item in history
                ),
                recommendation=(
                    "Reduce unnecessary redirect hops to improve "
                    "reliability, performance, and security visibility."
                ),
                url=response.url,
                category="redirects",
                metadata={
                    "redirect_count": redirect_count,
                },
            )
        )

    original_origin = _origin(original_url)

    external_redirects: list[str] = []

    for item in history:
        location = item.headers.get("location")

        if not location:
            continue

        try:
            destination = str(
                item.url.join(
                    httpx.URL(location)
                )
            )
        except Exception:
            continue

        destination_origin = _origin(destination)

        if destination_origin != original_origin:
            external_redirects.append(destination)

    if external_redirects:
        findings.append(
            Finding(
                id="external-redirect",
                title="External Redirect Observed",
                severity=Severity.INFO,
                description=(
                    "The observed redirect chain contains a destination "
                    "outside the original origin."
                ),
                evidence="\n".join(external_redirects),
                recommendation=(
                    "Review whether each external redirect is intentional "
                    "and controlled. Avoid accepting arbitrary redirect "
                    "destinations from untrusted input."
                ),
                url=response.url,
                category="redirects",
                metadata={
                    "external_destinations": external_redirects,
                },
            )
        )

    status_codes = [
        item.status_code
        for item in history
        if item.status_code in REDIRECT_CODES
    ]

    if status_codes:
        findings.append(
            Finding(
                id="redirect-chain-info",
                title="Redirect Chain Observed",
                severity=Severity.INFO,
                description=(
                    "One or more HTTP redirects were observed during "
                    "normal target access."
                ),
                evidence=", ".join(
                    str(code)
                    for code in status_codes
                ),
                recommendation=(
                    "Verify that redirects are intentional and that "
                    "destination URLs are appropriately controlled."
                ),
                url=response.url,
                category="redirects",
                metadata={
                    "status_codes": status_codes,
                },
            )
        )

    return findings
