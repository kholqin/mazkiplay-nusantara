from __future__ import annotations

from .evidence import Evidence
from .models import Confidence, SentinelFinding


def analyze_evidence(
    evidence: list[Evidence],
) -> list[SentinelFinding]:
    """
    Convert normalized evidence into deterministic findings.

    Evidence itself is not a vulnerability. Findings are produced
    only when the available evidence satisfies an explicit rule.
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
