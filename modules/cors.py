from __future__ import annotations

import httpx

from app.models import Finding, Severity


def check_cors(response: httpx.Response) -> list[Finding]:
    """
    Passively analyze CORS response headers.
    """

    findings: list[Finding] = []

    allow_origin = response.headers.get(
        "access-control-allow-origin"
    )
    allow_credentials = response.headers.get(
        "access-control-allow-credentials"
    )
    allow_methods = response.headers.get(
        "access-control-allow-methods"
    )
    allow_headers = response.headers.get(
        "access-control-allow-headers"
    )

    if not allow_origin:
        return findings

    origin_value = allow_origin.strip()
    credentials_value = (
        allow_credentials.strip().lower()
        if allow_credentials
        else ""
    )

    if origin_value == "*":
        severity = Severity.LOW

        if credentials_value == "true":
            severity = Severity.HIGH

            findings.append(
                Finding(
                    id="cors-wildcard-with-credentials",
                    title="CORS Wildcard With Credentials",
                    severity=severity,
                    description=(
                        "The response advertises a wildcard CORS origin "
                        "together with Access-Control-Allow-Credentials: true. "
                        "Review the effective CORS policy and browser behavior."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {origin_value}\n"
                        f"Access-Control-Allow-Credentials: "
                        f"{credentials_value}"
                    ),
                    recommendation=(
                        "Avoid wildcard origins for credentialed "
                        "cross-origin requests. Restrict allowed origins "
                        "to the application's trusted origins."
                    ),
                    url=response.url,
                    category="cors",
                )
            )

        else:
            findings.append(
                Finding(
                    id="cors-wildcard-origin",
                    title="CORS Allows Any Origin",
                    severity=severity,
                    description=(
                        "The response allows cross-origin requests from "
                        "any origin using a wildcard policy."
                    ),
                    evidence=(
                        f"Access-Control-Allow-Origin: {origin_value}"
                    ),
                    recommendation=(
                        "Use an explicit origin allowlist when "
                        "cross-origin access does not need to be public."
                    ),
                    url=response.url,
                    category="cors",
                )
            )

    if credentials_value == "true" and origin_value != "*":
        findings.append(
            Finding(
                id="cors-credentialed-origin",
                title="Credentialed CORS Policy Detected",
                severity=Severity.INFO,
                description=(
                    "The endpoint permits credentialed cross-origin "
                    "requests. Verify that the allowed origin is "
                    "strictly controlled."
                ),
                evidence=(
                    f"Access-Control-Allow-Origin: {origin_value}\n"
                    "Access-Control-Allow-Credentials: true"
                ),
                recommendation=(
                    "Maintain a strict trusted-origin allowlist and "
                    "avoid reflecting arbitrary Origin values."
                ),
                url=response.url,
                category="cors",
            )
        )

    if allow_methods:
        methods = {
            method.strip().upper()
            for method in allow_methods.split(",")
            if method.strip()
        }

        dangerous_methods = methods.intersection(
            {"PUT", "PATCH", "DELETE"}
        )

        if dangerous_methods:
            findings.append(
                Finding(
                    id="cors-sensitive-methods",
                    title="CORS Allows State-Changing Methods",
                    severity=Severity.INFO,
                    description=(
                        "The CORS policy advertises potentially "
                        "state-changing HTTP methods."
                    ),
                    evidence=(
                        "Access-Control-Allow-Methods: "
                        f"{allow_methods}"
                    ),
                    recommendation=(
                        "Allow only the HTTP methods required by the "
                        "cross-origin application."
                    ),
                    url=response.url,
                    category="cors",
                    metadata={
                        "methods": sorted(methods),
                        "sensitive_methods": sorted(dangerous_methods),
                    },
                )
            )

    if allow_headers:
        headers = {
            header.strip().lower()
            for header in allow_headers.split(",")
            if header.strip()
        }

        if "*" in headers:
            findings.append(
                Finding(
                    id="cors-wildcard-headers",
                    title="CORS Allows Wildcard Request Headers",
                    severity=Severity.LOW,
                    description=(
                        "The response permits a wildcard set of "
                        "request headers."
                    ),
                    evidence=(
                        "Access-Control-Allow-Headers: "
                        f"{allow_headers}"
                    ),
                    recommendation=(
                        "Restrict allowed request headers to those "
                        "actually required by the application."
                    ),
                    url=response.url,
                    category="cors",
                )
            )

    return findings
