from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """A single security observation produced by a scanner module."""

    id: str
    title: str
    severity: Severity
    description: str
    evidence: str | None = None
    recommendation: str | None = None
    url: HttpUrl | None = None
    category: str = "general"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanTarget(BaseModel):
    """Target metadata for an authorized security assessment."""

    url: HttpUrl
    hostname: str
    scheme: str
    port: int | None = None


class ScanResult(BaseModel):
    """Complete result of a scanner execution."""

    scanner: str = "Mazkiplay Nusantara"
    version: str = "0.1.0"
    target: ScanTarget
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)
    pages_scanned: int = 0
    requests_made: int = 0

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def finish(self) -> None:
        self.finished_at = datetime.now(timezone.utc)
