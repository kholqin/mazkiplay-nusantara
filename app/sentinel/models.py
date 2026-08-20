from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .evidence import Evidence
    from .fingerprint import HTTPFingerprint


# ============================================================
# ENUMS
# ============================================================

class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HostStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    LIVE = "LIVE"
    DEAD = "DEAD"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


# ============================================================
# HTTP COOKIE
# ============================================================

@dataclass(slots=True)
class HTTPCookieObservation:
    """Structured observation of one Set-Cookie header."""

    name: str
    value: str | None = None

    secure: bool = False
    httponly: bool = False

    samesite: str | None = None

    domain: str | None = None
    path: str | None = None

    max_age: str | None = None
    expires: str | None = None


# ============================================================
# TLS
# ============================================================

@dataclass(slots=True)
class TLSObservation:
    """
    Passive observation of a TLS endpoint.

    This model contains transport/certificate observations only.
    Vulnerability classification belongs to the analysis layer.
    """

    hostname: str
    port: int = 443

    connected: bool = False

    tls_version: str | None = None
    cipher: str | None = None

    subject: str | None = None
    issuer: str | None = None

    not_before: str | None = None
    not_after: str | None = None

    serial_number: str | None = None

    san: list[str] = field(
        default_factory=list
    )

    hostname_match: bool | None = None
    certificate_trusted: bool | None = None

    error: str | None = None


# ============================================================
# HTTP
# ============================================================

@dataclass(slots=True)
class HTTPObservation:
    """
    Raw HTTP/HTTPS observation.

    This model intentionally stores observations rather than
    declaring vulnerabilities. Analysis belongs to the
    fingerprinting/checking layer.
    """

    url: str

    final_url: str | None = None

    status_code: int | None = None

    response_time_ms: float | None = None

    content_type: str | None = None

    content_length: int | None = None

    server: str | None = None

    redirects: list[str] = field(
        default_factory=list
    )

    headers: dict[str, str] = field(
        default_factory=dict
    )

    cookies: list[str] = field(
        default_factory=list
    )

    cookie_observations: list[HTTPCookieObservation] = field(
        default_factory=list
    )

    error: str | None = None


# ============================================================
# HOST / SUBDOMAIN
# ============================================================

@dataclass(slots=True)
class HostAsset:
    hostname: str

    ips: list[str] = field(
        default_factory=list
    )

    status: HostStatus = HostStatus.UNKNOWN

    http_status: int | None = None

    https_status: int | None = None

    cname: str | None = None

    response_time_ms: float | None = None

    http: HTTPObservation | None = None


# ============================================================
# NETWORK / PORT
# ============================================================

@dataclass(slots=True)
class PortAsset:
    host: str

    port: int

    state: str = PortState.UNKNOWN.value

    service: str = "unknown"

    protocol: str = "tcp"

    banner: str | None = None

    response_time_ms: float | None = None


# ============================================================
# WEB ASSETS
# ============================================================

@dataclass(slots=True)
class WebAsset:
    url: str

    asset_type: str

    status_code: int | None = None

    content_type: str | None = None

    size: int | None = None

    source: str | None = None

    parent_url: str | None = None

    discovered_from: str | None = None


# ============================================================
# DNS
# ============================================================

@dataclass(slots=True)
class DNSProfile:
    a: list[str] = field(
        default_factory=list
    )

    aaaa: list[str] = field(
        default_factory=list
    )

    cname: list[str] = field(
        default_factory=list
    )

    mx: list[str] = field(
        default_factory=list
    )

    ns: list[str] = field(
        default_factory=list
    )

    txt: list[str] = field(
        default_factory=list
    )

    soa: list[str] = field(
        default_factory=list
    )


# ============================================================
# EXPOSURE / SEARCH REFERENCES
# ============================================================

@dataclass(slots=True)
class ExposureReference:
    query: str

    category: str

    description: str

    engine: str | None = None

    url: str | None = None


# ============================================================
# ARCHIVES
# ============================================================

@dataclass(slots=True)
class ArchiveReference:
    url: str

    timestamp: str | None = None

    source: str = "archive"

    original_url: str | None = None


# ============================================================
# SECURITY FINDING
# ============================================================

@dataclass(slots=True)
class SentinelFinding:
    finding_id: str

    title: str

    severity: str

    confidence: Confidence

    category: str

    description: str

    evidence: str | None = None

    recommendation: str | None = None

    url: str | None = None

    cwe: str | None = None

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


# ============================================================
# SCAN RESULT
# ============================================================

@dataclass(slots=True)
class SentinelResult:
    target: str

    started_at: str

    finished_at: str | None = None

    # Discovery
    dns: DNSProfile = field(
        default_factory=DNSProfile
    )

    hosts: list[HostAsset] = field(
        default_factory=list
    )

    ports: list[PortAsset] = field(
        default_factory=list
    )

    assets: list[WebAsset] = field(
        default_factory=list
    )

    http_observations: list[HTTPObservation] = field(
        default_factory=list
    )

    tls_observations: list[TLSObservation] = field(
        default_factory=list
    )

    fingerprints: list[HTTPFingerprint] = field(
        default_factory=list
    )

    evidence: list[Evidence] = field(
        default_factory=list
    )

    # Exposure intelligence
    exposures: list[ExposureReference] = field(
        default_factory=list
    )

    archives: list[ArchiveReference] = field(
        default_factory=list
    )

    # Security analysis
    findings: list[SentinelFinding] = field(
        default_factory=list
    )

    # Scan statistics
    requests: int = 0

    pages: int = 0

    hosts_discovered: int = 0

    ports_checked: int = 0

    assets_discovered: int = 0

    # Risk
    risk_score: int = 0

    # Metadata
    metadata: dict[str, Any] = field(
        default_factory=dict
    )
