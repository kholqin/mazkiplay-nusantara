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


def analyze_cookie_evidence(
    evidence: list[Evidence],
) -> list[SentinelFinding]:
    """
    Report observed cookies as informational findings.

    Structured cookie security attributes are evaluated
    separately by analyze_cookie_attributes().
    """

    findings: list[SentinelFinding] = []

    for item in evidence:
        if item.category != "cookie":
            continue

        cookie_name = item.metadata.get(
            "cookie_name",
            item.value or "unknown",
        )

        findings.append(
            SentinelFinding(
                finding_id=f"cookie-observed:{item.evidence_id}",
                title=f"Cookie observed: {cookie_name}",
                severity="info",
                confidence=Confidence.HIGH,
                category="cookie",
                description=(
                    "An HTTP cookie was observed in the response. "
                    "Cookie security attributes are not evaluated "
                    "by this rule."
                ),
                evidence=item.value,
                recommendation=(
                    "Review the cookie configuration separately "
                    "for Secure, HttpOnly, SameSite, Domain, and Path "
                    "attributes."
                ),
                url=item.url,
                metadata={
                    "evidence_id": item.evidence_id,
                    "cookie_name": cookie_name,
                    "analysis": "observation-only",
                },
            )
        )

    return findings


def analyze_cookie_attributes(
    evidence: list[Evidence],
) -> list[SentinelFinding]:
    """
    Analyze structured cookie security attributes.

    This rule evaluates only normalized cookie metadata.
    Missing attributes are configuration observations, not
    automatically confirmed vulnerabilities.
    """

    findings: list[SentinelFinding] = []

    for item in evidence:
        if item.category != "cookie":
            continue

        if item.metadata.get("structured") != "true":
            continue

        cookie_name = item.metadata.get(
            "cookie_name",
            "unknown",
        )

        base_metadata = {
            "evidence_id": item.evidence_id,
            "cookie_name": cookie_name,
            "analysis": "attribute-review",
        }

        if item.metadata.get("secure") != "true":
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-secure-missing:{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie Secure attribute not observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The observed cookie does not include "
                        "the Secure attribute."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether the cookie should be "
                        "restricted to HTTPS with the Secure attribute."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "secure",
                        "observed": "false",
                    },
                )
            )

        if item.metadata.get("httponly") != "true":
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-httponly-missing:{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie HttpOnly attribute not observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The observed cookie does not include "
                        "the HttpOnly attribute."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether client-side JavaScript access "
                        "is required. If not, consider HttpOnly."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "httponly",
                        "observed": "false",
                    },
                )
            )

        samesite = item.metadata.get(
            "samesite",
            "",
        ).lower()

        if not samesite:
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-samesite-missing:{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie SameSite attribute not observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The observed cookie does not include "
                        "a SameSite attribute."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether an explicit SameSite policy "
                        "such as Lax or Strict is appropriate."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "samesite",
                        "observed": "false",
                    },
                )
            )

        if (
            samesite == "none"
            and item.metadata.get("secure") != "true"
        ):
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-samesite-none-insecure:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"SameSite=None without Secure: "
                        f"{cookie_name}"
                    ),
                    severity="low",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The observed cookie declares SameSite=None "
                        "without the Secure attribute."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review the cookie configuration and add "
                        "Secure when SameSite=None is intentionally used."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "samesite-none",
                        "observed": "insecure",
                    },
                )
            )

    return findings
