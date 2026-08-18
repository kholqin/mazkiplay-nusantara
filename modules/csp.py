from __future__ import annotations

import httpx

from app.models import Finding, Severity


def parse_csp(value: str) -> dict[str, list[str]]:
    """
    Parse a Content-Security-Policy header into directives.
    """

    directives: dict[str, list[str]] = {}

    for raw_directive in value.split(";"):
        parts = raw_directive.strip().split()

        if not parts:
            continue

        name = parts[0].lower()
        sources = parts[1:]

        directives[name] = sources

    return directives


def check_csp(
    response: httpx.Response,
) -> list[Finding]:
    """
    Perform passive CSP analysis.
    """

    findings: list[Finding] = []

    csp = response.headers.get(
        "content-security-policy"
    )

    if not csp:
        return findings

    directives = parse_csp(csp)

    script_src = directives.get(
        "script-src",
        directives.get("default-src", []),
    )

    object_src = directives.get(
        "object-src",
        [],
    )

    base_uri = directives.get(
        "base-uri",
        [],
    )

    frame_ancestors = directives.get(
        "frame-ancestors",
        [],
    )

    if "*" in script_src:
        findings.append(
            Finding(
                id="csp-script-wildcard",
                title="CSP script-src Uses Wildcard",
                severity=Severity.MEDIUM,
                description=(
                    "The effective script source policy contains a "
                    "wildcard source."
                ),
                evidence=csp,
                recommendation=(
                    "Restrict script sources to trusted origins and "
                    "prefer nonces or hashes for inline scripts."
                ),
                url=response.url,
                category="csp",
            )
        )

    if "'unsafe-inline'" in {
        item.lower()
        for item in script_src
    }:
        findings.append(
            Finding(
                id="csp-unsafe-inline",
                title="CSP Allows unsafe-inline",
                severity=Severity.LOW,
                description=(
                    "The effective script policy permits inline scripts."
                ),
                evidence=csp,
                recommendation=(
                    "Replace unsafe-inline with nonces or hashes "
                    "where practical."
                ),
                url=response.url,
                category="csp",
            )
        )

    if "'unsafe-eval'" in {
        item.lower()
        for item in script_src
    }:
        findings.append(
            Finding(
                id="csp-unsafe-eval",
                title="CSP Allows unsafe-eval",
                severity=Severity.LOW,
                description=(
                    "The effective script policy permits "
                    "string-to-code evaluation."
                ),
                evidence=csp,
                recommendation=(
                    "Remove unsafe-eval unless it is required by "
                    "the application's runtime."
                ),
                url=response.url,
                category="csp",
            )
        )

    if "object-src" not in directives:
        findings.append(
            Finding(
                id="csp-object-src-missing",
                title="CSP Missing object-src",
                severity=Severity.LOW,
                description=(
                    "The policy does not explicitly define object-src."
                ),
                evidence=csp,
                recommendation=(
                    "Consider setting object-src to 'none' when "
                    "legacy plugin content is unnecessary."
                ),
                url=response.url,
                category="csp",
            )
        )

    elif "'none'" not in {
        item.lower()
        for item in object_src
    }:
        findings.append(
            Finding(
                id="csp-object-src-permissive",
                title="CSP object-src Is Not Restricted",
                severity=Severity.LOW,
                description=(
                    "object-src is defined but does not explicitly "
                    "restrict plugin/object content to 'none'."
                ),
                evidence=f"object-src: {' '.join(object_src)}",
                recommendation=(
                    "Use object-src 'none' when object/plugin content "
                    "is not required."
                ),
                url=response.url,
                category="csp",
            )
        )

    if "base-uri" not in directives:
        findings.append(
            Finding(
                id="csp-base-uri-missing",
                title="CSP Missing base-uri",
                severity=Severity.INFO,
                description=(
                    "The CSP does not explicitly define base-uri."
                ),
                evidence=csp,
                recommendation=(
                    "Consider restricting base-uri if the application "
                    "does not require arbitrary base URLs."
                ),
                url=response.url,
                category="csp",
            )
        )

    if "frame-ancestors" not in directives:
        findings.append(
            Finding(
                id="csp-frame-ancestors-missing",
                title="CSP Missing frame-ancestors",
                severity=Severity.INFO,
                description=(
                    "The CSP does not define frame-ancestors."
                ),
                evidence=csp,
                recommendation=(
                    "Define frame-ancestors when the application "
                    "requires explicit framing restrictions."
                ),
                url=response.url,
                category="csp",
            )
        )

    findings.append(
        Finding(
            id="csp-policy-summary",
            title="CSP Policy Analyzed",
            severity=Severity.INFO,
            description=(
                "The Content-Security-Policy was successfully parsed "
                "and analyzed."
            ),
            evidence=csp,
            url=response.url,
            category="csp",
            metadata={
                "directives": directives,
            },
        )
    )

    return findings
