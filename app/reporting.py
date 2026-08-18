from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, ScanResult


def build_scan_result(
    target,
    findings: list[Finding],
    pages_scanned: int = 1,
    requests_made: int = 1,
) -> ScanResult:
    """
    Build a complete ScanResult object.
    """

    result = ScanResult(
        target=target,
        findings=findings,
        pages_scanned=pages_scanned,
        requests_made=requests_made,
    )

    result.finish()

    return result


def save_json_report(
    result: ScanResult,
    directory: str | Path = "reports",
) -> Path:
    """
    Save a ScanResult as a formatted JSON report.
    """

    output_dir = Path(directory)
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d-%H%M%S")

    hostname = (
        result.target.hostname
        .replace(".", "_")
        .replace(":", "_")
    )

    filename = (
        f"scan-{hostname}-{timestamp}.json"
    )

    output_path = output_dir / filename

    payload = result.model_dump(
        mode="json"
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            payload,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")

    return output_path


def summarize_findings(
    findings: list[Finding],
) -> dict[str, int]:
    """
    Return a severity summary.
    """

    summary = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.severity.value

        if severity in summary:
            summary[severity] += 1

    return summary
