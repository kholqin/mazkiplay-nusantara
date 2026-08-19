from __future__ import annotations

from .evidence import Evidence, SECURITY_HEADER_DESCRIPTIONS
from .models import Confidence, HTTPObservation, SentinelFinding


def analyze_evidence(
    evidence: list[Evidence],
) -> list[SentinelFinding]:
    """
    Convert normalized evidence into deterministic findings.

    Evidence itself is not a vulnerability. Findings are produced
    only when an explicit analysis rule is satisfied.
    """

    findings: list[SentinelFinding] = []

    for item in evidence:
        if item.category != "security-header":
            continue

        findings.append(
            SentinelFinding(
                finding_id=(
                    f"header-present:{item.evidence_id}"
                ),
                title=f"{item.title} observed",
                severity="info",
                confidence=Confidence.HIGH,
                category="security-header",
                description=(
                    f"{item.title} is configured on the "
                    "observed HTTP response."
                ),
                evidence=item.value,
                recommendation=None,
                url=item.url,
                metadata={
                    "evidence_id": item.evidence_id,
                    "header": item.metadata.get(
                        "header",
                        "",
                    ),
                },
            )
        )

    return findings


def analyze_missing_security_headers(
    observation: HTTPObservation,
) -> list[SentinelFinding]:
    """
    Report security headers that were not observed.

    Missing headers are configuration observations, not
    automatically confirmed vulnerabilities.
    """

    findings: list[SentinelFinding] = []

    observed = {
        header.lower()
        for header in observation.headers
    }

    for header, title in SECURITY_HEADER_DESCRIPTIONS.items():
        if header in observed:
            continue

        findings.append(
            SentinelFinding(
                finding_id=f"header-missing:{header}",
                title=f"{title} not observed",
                severity="info",
                confidence=Confidence.HIGH,
                category="security-header",
                description=(
                    f"{title} was not observed in the "
                    "HTTP response."
                ),
                evidence=None,
                recommendation=(
                    f"Review whether {title} should be "
                    "enabled for this application."
                ),
                url=(
                    observation.final_url
                    or observation.url
                ),
                metadata={
                    "header": header,
                    "observation": "missing",
                },
            )
        )

    return findings
