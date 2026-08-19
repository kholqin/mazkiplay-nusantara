from __future__ import annotations

import re

import httpx

from app.models import Finding, Severity


DISCLOSURE_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
    "x-generator": "X-Generator",
}


VERSION_PATTERN = re.compile(
    r"(?i)(?:php|apache|nginx|iis|asp\.net|express|node(?:\.js)?)"
    r"[/\s-]*v?[\d]+(?:\.[\d]+){0,3}"
)


def check_disclosure(response: httpx.Response) -> list[Finding]:
    """
    Passively inspect response headers for technology/version disclosure.
    """

    findings: list[Finding] = []

    for header_name, display_name in DISCLOSURE_HEADERS.items():
        value = response.headers.get(header_name)

        if not value:
            continue

        findings.append(
            Finding(
                id=f"disclosure-{header_name.replace('-', '_')}",
                title=f"{display_name} Header Disclosure",
                severity=Severity.LOW,
                description=(
                    f"The response exposes the {display_name} header. "
                    "Depending on its value, this may reveal unnecessary "
                    "implementation details."
                ),
                evidence=f"{display_name}: {value}",
                recommendation=(
                    "Remove or minimize unnecessary technology and "
                    "version information from public HTTP responses."
                ),
                url=str(response.url),
                category="information-disclosure",
                metadata={
                    "header": display_name,
                    "value": value,
                },
            )
        )

    for header_name, value in response.headers.items():
        matches = VERSION_PATTERN.findall(value)

        if not matches:
            continue

        findings.append(
            Finding(
                id=(
                    "technology-version-"
                    f"{header_name.lower().replace('-', '_')}"
                ),
                title="Technology Version Disclosure",
                severity=Severity.INFO,
                description=(
                    "A response header appears to expose a recognizable "
                    "technology and version pattern."
                ),
                evidence=f"{header_name}: {value}",
                recommendation=(
                    "Consider minimizing public technology/version "
                    "disclosure where operationally appropriate."
                ),
                url=str(response.url),
                category="information-disclosure",
                metadata={
                    "header": header_name,
                    "matches": matches,
                },
            )
        )

    return _deduplicate_findings(findings)


def _deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """
    Remove duplicate findings generated from overlapping checks.
    """

    unique: dict[str, Finding] = {}

    for finding in findings:
        key = (
            f"{finding.id}:"
            f"{finding.url}:"
            f"{finding.evidence}"
        )

        unique[key] = finding

    return list(unique.values())
