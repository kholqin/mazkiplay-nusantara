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

        elif samesite not in {
            "lax",
            "strict",
            "none",
        }:
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-samesite-invalid:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"Unrecognized SameSite value: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The observed cookie contains a SameSite "
                        "value outside the recognized Lax, Strict, "
                        "or None values."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review the cookie configuration and use "
                        "a supported SameSite policy."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "samesite-invalid",
                        "observed": samesite,
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

        # Domain and Path policy observations.
        #
        # A Domain attribute broadens cookie scope to the
        # specified domain and potentially its subdomains.
        # This is an informational policy observation, not
        # automatically a vulnerability.
        domain = item.metadata.get("domain", "")

        if domain:
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-domain-present:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie Domain attribute observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The cookie includes a Domain attribute, "
                        "which broadens its cookie scope beyond "
                        "host-only behavior."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether the Domain attribute is "
                        "required. Prefer host-only cookies when "
                        "cross-subdomain sharing is unnecessary."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "domain-present",
                        "observed": domain,
                    },
                )
            )

        # Path controls which request paths receive the cookie.
        # Report non-root paths as informational policy observations.
        path = item.metadata.get("path", "")

        if path and path != "/":
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-path-present:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie Path attribute observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The cookie uses a Path attribute other "
                        "than the root path."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether the cookie Path is "
                        "appropriately scoped for the application."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "path-present",
                        "observed": path,
                    },
                )
            )

        # Cookie lifetime policy observations.
        #
        # Max-Age and Expires describe cookie lifetime. Their
        # presence alone is informational and is not automatically
        # treated as a vulnerability.

        max_age = item.metadata.get(
            "max_age",
            "",
        )

        if max_age:
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-max-age-present:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie Max-Age attribute observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The cookie includes a Max-Age attribute "
                        "that defines its lifetime in seconds."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether the configured cookie "
                        "lifetime is appropriate for the sensitivity "
                        "and purpose of the cookie."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "max-age-present",
                        "observed": max_age,
                    },
                )
            )

        expires = item.metadata.get(
            "expires",
            "",
        )

        if expires:
            findings.append(
                SentinelFinding(
                    finding_id=(
                        f"cookie-expires-present:"
                        f"{item.evidence_id}"
                    ),
                    title=(
                        f"Cookie Expires attribute observed: "
                        f"{cookie_name}"
                    ),
                    severity="info",
                    confidence=Confidence.HIGH,
                    category="cookie",
                    description=(
                        "The cookie includes an Expires attribute "
                        "that defines an absolute expiration time."
                    ),
                    evidence=item.value,
                    recommendation=(
                        "Review whether the configured expiration "
                        "time is appropriate for the cookie."
                    ),
                    url=item.url,
                    metadata={
                        **base_metadata,
                        "attribute": "expires-present",
                        "observed": expires,
                    },
                )
            )

        # Cookie prefix rules.
        #
        # __Secure- cookies must carry Secure.
        if cookie_name.startswith("__Secure-"):
            if item.metadata.get("secure") != "true":
                findings.append(
                    SentinelFinding(
                        finding_id=(
                            f"cookie-secure-prefix:{item.evidence_id}"
                        ),
                        title=(
                            f"__Secure- cookie without Secure: "
                            f"{cookie_name}"
                        ),
                        severity="low",
                        confidence=Confidence.HIGH,
                        category="cookie",
                        description=(
                            "The cookie uses the __Secure- prefix "
                            "but the Secure attribute was not observed."
                        ),
                        evidence=item.value,
                        recommendation=(
                            "Review the cookie configuration and "
                            "ensure the Secure attribute is present."
                        ),
                        url=item.url,
                        metadata={
                            **base_metadata,
                            "attribute": "secure-prefix",
                            "observed": "false",
                        },
                    )
                )

        # __Host- cookies require:
        #   Secure
        #   Path=/
        #   no Domain attribute
        if cookie_name.startswith("__Host-"):
            if item.metadata.get("secure") != "true":
                findings.append(
                    SentinelFinding(
                        finding_id=(
                            f"cookie-host-prefix-secure:"
                            f"{item.evidence_id}"
                        ),
                        title=(
                            f"__Host- cookie without Secure: "
                            f"{cookie_name}"
                        ),
                        severity="low",
                        confidence=Confidence.HIGH,
                        category="cookie",
                        description=(
                            "The cookie uses the __Host- prefix "
                            "but the Secure attribute was not observed."
                        ),
                        evidence=item.value,
                        recommendation=(
                            "Ensure the __Host- cookie includes "
                            "the Secure attribute."
                        ),
                        url=item.url,
                        metadata={
                            **base_metadata,
                            "attribute": "host-prefix-secure",
                            "observed": "false",
                        },
                    )
                )

            if item.metadata.get("domain", ""):
                findings.append(
                    SentinelFinding(
                        finding_id=(
                            f"cookie-host-prefix-domain:"
                            f"{item.evidence_id}"
                        ),
                        title=(
                            f"__Host- cookie defines Domain: "
                            f"{cookie_name}"
                        ),
                        severity="low",
                        confidence=Confidence.HIGH,
                        category="cookie",
                        description=(
                            "The cookie uses the __Host- prefix "
                            "but a Domain attribute was observed."
                        ),
                        evidence=item.value,
                        recommendation=(
                            "Remove the Domain attribute from "
                            "the __Host- cookie."
                        ),
                        url=item.url,
                        metadata={
                            **base_metadata,
                            "attribute": "host-prefix-domain",
                            "observed": "true",
                        },
                    )
                )

            if item.metadata.get("path", "") != "/":
                findings.append(
                    SentinelFinding(
                        finding_id=(
                            f"cookie-host-prefix-path:"
                            f"{item.evidence_id}"
                        ),
                        title=(
                            f"__Host- cookie Path is not /: "
                            f"{cookie_name}"
                        ),
                        severity="low",
                        confidence=Confidence.HIGH,
                        category="cookie",
                        description=(
                            "The cookie uses the __Host- prefix "
                            "but its Path attribute was not observed "
                            "as '/'."
                        ),
                        evidence=item.value,
                        recommendation=(
                            "Set Path=/ for the __Host- cookie."
                        ),
                        url=item.url,
                        metadata={
                            **base_metadata,
                            "attribute": "host-prefix-path",
                            "observed": item.metadata.get(
                                "path",
                                "",
                            ),
                        },
                    )
                )

    return findings
