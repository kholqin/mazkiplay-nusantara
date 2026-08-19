from __future__ import annotations

from collections.abc import Iterable

import httpx

from app.models import Finding, Severity


SECURITY_HEADERS: dict[
    str,
    tuple[Severity, str, str, str],
] = {
    "strict-transport-security": (
        Severity.MEDIUM,
        "Missing HSTS",
        (
            "The server does not advertise HTTP Strict Transport Security. "
            "HTTPS-only enforcement is therefore not communicated to browsers."
        ),
        "Enable Strict-Transport-Security on HTTPS responses.",
    ),
    "content-security-policy": (
        Severity.MEDIUM,
        "Missing Content Security Policy",
        (
            "No Content-Security-Policy header was detected. "
            "Browser-side resource restrictions may therefore be weaker."
        ),
        "Define and deploy an appropriate Content-Security-Policy.",
    ),
    "x-content-type-options": (
        Severity.LOW,
        "Missing X-Content-Type-Options",
        (
            "The response does not explicitly disable MIME type sniffing."
        ),
        "Set X-Content-Type-Options to nosniff.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Missing Clickjacking Protection",
        (
            "No X-Frame-Options header was detected. "
            "Review whether the application can safely be embedded."
        ),
        "Use an appropriate X-Frame-Options policy or CSP frame-ancestors.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Missing Referrer-Policy",
        (
            "The application does not explicitly define browser "
            "referrer-information handling."
        ),
        "Set an explicit Referrer-Policy.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Missing Permissions-Policy",
        (
            "The response does not define browser feature permissions."
        ),
        "Define a restrictive Permissions-Policy appropriate for the application.",
    ),
}


def check_security_headers(
    response: httpx.Response,
) -> list[Finding]:
    """
    Analyze security-related HTTP response headers.

    This function performs passive analysis only; it does not
    modify the target or send additional attack payloads.
    """

    findings: list[Finding] = []

    headers = {
        key.lower(): value.strip()
        for key, value in response.headers.items()
    }

    for header_name, (
        severity,
        title,
        description,
        recommendation,
    ) in SECURITY_HEADERS.items():

        if header_name not in headers:
            findings.append(
                Finding(
                    id=f"missing-{header_name.replace('-', '_')}",
                    title=title,
                    severity=severity,
                    description=description,
                    recommendation=recommendation,
                    url=str(response.url),
                    category="security-headers",
                    metadata={
                        "header": header_name,
                        "status_code": response.status_code,
                    },
                )
            )

    return findings


def check_header_values(
    response: httpx.Response,
) -> list[Finding]:
    """
    Perform basic value-level checks on security headers.
    """

    findings: list[Finding] = []

    headers = {
        key.lower(): value.strip()
        for key, value in response.headers.items()
    }

    csp = headers.get("content-security-policy")

    if csp and "unsafe-inline" in csp.lower():
        findings.append(
            Finding(
                id="csp-unsafe-inline",
                title="CSP Allows unsafe-inline",
                severity=Severity.LOW,
                description=(
                    "The Content-Security-Policy contains "
                    "'unsafe-inline', which can weaken script restrictions."
                ),
                evidence=csp,
                recommendation=(
                    "Prefer nonces or hashes instead of unsafe-inline "
                    "where application architecture permits."
                ),
                url=str(response.url),
                category="security-headers",
            )
        )

    if csp and "unsafe-eval" in csp.lower():
        findings.append(
            Finding(
                id="csp-unsafe-eval",
                title="CSP Allows unsafe-eval",
                severity=Severity.LOW,
                description=(
                    "The Content-Security-Policy contains "
                    "'unsafe-eval', reducing script execution restrictions."
                ),
                evidence=csp,
                recommendation=(
                    "Remove unsafe-eval unless it is strictly required "
                    "by the application."
                ),
                url=str(response.url),
                category="security-headers",
            )
        )

    hsts = headers.get("strict-transport-security")

    if hsts:
        max_age = _extract_max_age(hsts)

        if max_age is not None and max_age < 15_552_000:
            findings.append(
                Finding(
                    id="hsts-short-max-age",
                    title="Short HSTS max-age",
                    severity=Severity.LOW,
                    description=(
                        "The HSTS max-age is shorter than approximately "
                        "180 days."
                    ),
                    evidence=hsts,
                    recommendation=(
                        "Consider a longer HSTS max-age after validating "
                        "HTTPS readiness across the domain."
                    ),
                    url=str(response.url),
                    category="security-headers",
                    metadata={"max_age": max_age},
                )
            )

    return findings


def _extract_max_age(value: str) -> int | None:
    for directive in value.split(";"):
        directive = directive.strip()

        if "=" not in directive:
            continue

        name, raw_value = directive.split("=", 1)

        if name.strip().lower() != "max-age":
            continue

        try:
            return int(raw_value.strip())
        except ValueError:
            return None

    return None


def run_header_checks(
    response: httpx.Response,
) -> list[Finding]:
    """
    Execute all header-related passive checks.
    """

    findings: list[Finding] = []

    findings.extend(check_security_headers(response))
    findings.extend(check_header_values(response))

    return findings
