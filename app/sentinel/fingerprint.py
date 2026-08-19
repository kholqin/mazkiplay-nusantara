from __future__ import annotations

from dataclasses import dataclass, field

from .models import HTTPObservation


@dataclass(slots=True)
class Fingerprint:
    name: str
    category: str
    confidence: str
    evidence: str


@dataclass(slots=True)
class HTTPFingerprint:
    technologies: list[Fingerprint] = field(
        default_factory=list
    )

    security_headers: dict[str, bool] = field(
        default_factory=dict
    )

    cookie_flags: dict[str, dict[str, bool]] = field(
        default_factory=dict
    )

    status_class: str = "unknown"

    is_api_hint: bool = False

    is_cdn_hint: bool = False

    is_waf_hint: bool = False


SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


def classify_status(
    status_code: int | None,
) -> str:
    if status_code is None:
        return "unknown"

    if 100 <= status_code < 200:
        return "informational"

    if 200 <= status_code < 300:
        return "success"

    if 300 <= status_code < 400:
        return "redirect"

    if 400 <= status_code < 500:
        return "client-error"

    if 500 <= status_code < 600:
        return "server-error"

    return "unknown"


def detect_security_headers(
    observation: HTTPObservation,
) -> dict[str, bool]:

    return {
        header: header in observation.headers
        for header in SECURITY_HEADERS
    }


def detect_server(
    observation: HTTPObservation,
) -> list[Fingerprint]:

    fingerprints: list[Fingerprint] = []

    server = observation.server

    if not server:
        return fingerprints

    value = server.lower()

    fingerprints.append(
        Fingerprint(
            name=server,
            category="server",
            confidence="HIGH",
            evidence=f"Server header: {server}",
        )
    )

    signatures = {
        "nginx": "nginx",
        "apache": "Apache HTTP Server",
        "cloudflare": "Cloudflare",
        "microsoft-iis": "Microsoft IIS",
        "iis": "Microsoft IIS",
        "caddy": "Caddy",
        "openresty": "OpenResty",
    }

    for marker, name in signatures.items():
        if marker in value:
            fingerprints.append(
                Fingerprint(
                    name=name,
                    category="web-server",
                    confidence="HIGH",
                    evidence=(
                        f"Server header matched: {server}"
                    ),
                )
            )

    return fingerprints


def detect_headers(
    observation: HTTPObservation,
) -> list[Fingerprint]:

    fingerprints: list[Fingerprint] = []

    headers = observation.headers

    signatures = {
        "x-powered-by": "Application runtime hint",
        "x-generator": "Application generator hint",
        "x-aspnet-version": "ASP.NET",
        "x-aspnetmvc-version": "ASP.NET MVC",
        "via": "Proxy/CDN hint",
    }

    for header, name in signatures.items():

        if header not in headers:
            continue

        value = headers[header]

        fingerprints.append(
            Fingerprint(
                name=name,
                category="header",
                confidence="MEDIUM",
                evidence=(
                    f"{header}: {value}"
                ),
            )
        )

    return fingerprints


def detect_platform_hints(
    observation: HTTPObservation,
) -> list[Fingerprint]:

    fingerprints: list[Fingerprint] = []

    headers = observation.headers

    if "cf-ray" in headers:
        fingerprints.append(
            Fingerprint(
                name="Cloudflare",
                category="cdn",
                confidence="HIGH",
                evidence="CF-Ray header observed.",
            )
        )

    if "server" in headers:
        server = headers["server"].lower()

        if "cloudflare" in server:
            fingerprints.append(
                Fingerprint(
                    name="Cloudflare",
                    category="cdn",
                    confidence="HIGH",
                    evidence=(
                        "Cloudflare identified "
                        "from Server header."
                    ),
                )
            )

    if (
        "x-cache" in headers
        or "age" in headers
    ):
        fingerprints.append(
            Fingerprint(
                name="Caching layer",
                category="infrastructure",
                confidence="MEDIUM",
                evidence=(
                    "Cache-related response headers "
                    "were observed."
                ),
            )
        )

    return fingerprints


def detect_api_hint(
    observation: HTTPObservation,
) -> bool:

    url = (
        observation.final_url
        or observation.url
    ).lower()

    content_type = (
        observation.content_type or ""
    ).lower()

    return (
        "/api/" in url
        or url.endswith("/api")
        or "application/json" in content_type
        or "application/problem+json" in content_type
    )


def detect_cdn_hint(
    observation: HTTPObservation,
) -> bool:

    headers = observation.headers

    markers = {
        "cf-ray",
        "x-cache",
        "x-cdn",
        "x-served-by",
        "via",
    }

    return any(
        marker in headers
        for marker in markers
    )


def detect_waf_hint(
    observation: HTTPObservation,
) -> bool:

    headers = observation.headers

    waf_markers = {
        "cf-ray",
        "x-sucuri-id",
        "x-sucuri-cache",
        "x-waf",
    }

    return any(
        marker in headers
        for marker in waf_markers
    )


def fingerprint_http(
    observation: HTTPObservation,
) -> HTTPFingerprint:

    technologies: list[Fingerprint] = []

    technologies.extend(
        detect_server(observation)
    )

    technologies.extend(
        detect_headers(observation)
    )

    technologies.extend(
        detect_platform_hints(observation)
    )

    return HTTPFingerprint(
        technologies=technologies,
        security_headers=detect_security_headers(
            observation
        ),
        status_class=classify_status(
            observation.status_code
        ),
        is_api_hint=detect_api_hint(
            observation
        ),
        is_cdn_hint=detect_cdn_hint(
            observation
        ),
        is_waf_hint=detect_waf_hint(
            observation
        ),
    )
