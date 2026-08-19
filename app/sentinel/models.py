from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class HostStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    LIVE = "LIVE"
    DEAD = "DEAD"


@dataclass(slots=True)
class HostAsset:
    hostname: str
    ips: list[str] = field(default_factory=list)
    status: HostStatus = HostStatus.UNKNOWN
    http_status: int | None = None
    https_status: int | None = None
    cname: str | None = None
    response_time_ms: float | None = None


@dataclass(slots=True)
class PortAsset:
    host: str
    port: int
    state: str
    service: str = "unknown"
    protocol: str = "tcp"


@dataclass(slots=True)
class WebAsset:
    url: str
    asset_type: str
    status_code: int | None = None
    content_type: str | None = None
    size: int | None = None
    source: str | None = None


@dataclass(slots=True)
class DNSProfile:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    soa: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ExposureReference:
    query: str
    category: str
    description: str


@dataclass(slots=True)
class ArchiveReference:
    url: str
    timestamp: str | None = None
    source: str = "archive"


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
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SentinelResult:
    target: str
    started_at: str
    finished_at: str | None = None

    dns: DNSProfile = field(default_factory=DNSProfile)

    hosts: list[HostAsset] = field(default_factory=list)
    ports: list[PortAsset] = field(default_factory=list)
    assets: list[WebAsset] = field(default_factory=list)

    exposures: list[ExposureReference] = field(
        default_factory=list
    )

    archives: list[ArchiveReference] = field(
        default_factory=list
    )

    findings: list[SentinelFinding] = field(
        default_factory=list
    )

    requests: int = 0
    pages: int = 0

    risk_score: int = 0

