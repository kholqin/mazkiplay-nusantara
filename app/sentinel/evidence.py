from __future__ import annotations

from dataclasses import dataclass, field

from .cookies import cookie_metadata
from .models import HTTPObservation


@dataclass(slots=True)
class Evidence:
    """
    Normalized security-relevant observation.

    Evidence is not a vulnerability finding.
    A later analysis layer decides whether evidence
    is sufficient to produce a finding.
    """

    evidence_id: str
    category: str
    title: str
    value: str | None = None
    url: str | None = None
    confidence: str = "LOW"
    metadata: dict[str, str] = field(
        default_factory=dict
    )


SECURITY_HEADER_DESCRIPTIONS = {
    "strict-transport-security":
        "HTTP Strict Transport Security",
    "content-security-policy":
        "Content Security Policy",
    "x-content-type-options":
        "X-Content-Type-Options",
    "x-frame-options":
        "X-Frame-Options",
    "referrer-policy":
        "Referrer Policy",
    "permissions-policy":
        "Permissions Policy",
}


def collect_header_evidence(
    observation: HTTPObservation,
) -> list[Evidence]:
    evidence: list[Evidence] = []

    for header, title in (
        SECURITY_HEADER_DESCRIPTIONS.items()
    ):
        if header not in observation.headers:
            continue

        value = observation.headers[header]

        evidence.append(
            Evidence(
                evidence_id=f"header:{header}",
                category="security-header",
                title=title,
                value=value,
                url=(
                    observation.final_url
                    or observation.url
                ),
                confidence="HIGH",
                metadata={
                    "header": header,
                },
            )
        )

    return evidence


def collect_cookie_evidence(
    observation: HTTPObservation,
) -> list[Evidence]:
    evidence: list[Evidence] = []

    # Prefer structured cookie observations.
    # Cookie values are deliberately redacted before they
    # enter the evidence/reporting layer.
    for index, cookie in enumerate(
        observation.cookie_observations
    ):
        metadata = cookie_metadata(cookie)

        evidence.append(
            Evidence(
                evidence_id=f"cookie:{index}:{cookie.name}",
                category="cookie",
                title="Observed HTTP cookie",
                value=metadata["value"],
                url=(
                    observation.final_url
                    or observation.url
                ),
                confidence="HIGH",
                metadata={
                    "cookie_name": metadata["cookie_name"],
                    "role": metadata["role"],
                    "secure": metadata["secure"],
                    "httponly": metadata["httponly"],
                    "samesite": metadata["samesite"],
                    "domain": metadata["domain"],
                    "path": metadata["path"],
                    "max_age": metadata["max_age"],
                    "expires": metadata["expires"],
                    "structured": "true",
                    "redacted": "true",
                },
            )
        )

    # Backward-compatible fallback for observations that only
    # contain the legacy cookie-name list.
    if not observation.cookie_observations:
        for cookie_name in observation.cookies:
            evidence.append(
                Evidence(
                    evidence_id=f"cookie:{cookie_name}",
                    category="cookie",
                    title="Observed HTTP cookie",
                    value="[REDACTED]",
                    url=(
                        observation.final_url
                        or observation.url
                    ),
                    confidence="HIGH",
                    metadata={
                        "cookie_name": cookie_name,
                        "role": "unknown",
                        "structured": "false",
                        "redacted": "true",
                    },
                )
            )

    return evidence


def collect_redirect_evidence(
    observation: HTTPObservation,
) -> list[Evidence]:
    evidence: list[Evidence] = []

    for index, redirect in enumerate(
        observation.redirects
    ):
        evidence.append(
            Evidence(
                evidence_id=(
                    f"redirect:{index}:{redirect}"
                ),
                category="redirect",
                title="Observed redirect",
                value=redirect,
                url=(
                    observation.final_url
                    or observation.url
                ),
                confidence="HIGH",
                metadata={
                    "index": str(index),
                },
            )
        )

    return evidence


def collect_http_evidence(
    observation: HTTPObservation,
) -> list[Evidence]:
    """
    Convert one HTTP observation into normalized evidence.
    """

    evidence: list[Evidence] = []

    evidence.extend(
        collect_header_evidence(
            observation
        )
    )

    evidence.extend(
        collect_cookie_evidence(
            observation
        )
    )

    evidence.extend(
        collect_redirect_evidence(
            observation
        )
    )

    if observation.server:
        evidence.append(
            Evidence(
                evidence_id="server-header",
                category="technology",
                title="Observed server header",
                value=observation.server,
                url=(
                    observation.final_url
                    or observation.url
                ),
                confidence="HIGH",
            )
        )

    if observation.content_type:
        evidence.append(
            Evidence(
                evidence_id="content-type",
                category="http",
                title="Observed content type",
                value=observation.content_type,
                url=(
                    observation.final_url
                    or observation.url
                ),
                confidence="HIGH",
            )
        )

    return evidence
