import json

from app.models import Finding, ScanTarget, Severity
from app.reporting import (
    build_scan_result,
    save_json_report,
    summarize_findings,
)


def make_target():
    return ScanTarget(
        url="https://example.com/",
        hostname="example.com",
        scheme="https",
        port=443,
    )


def make_finding(
    finding_id="test",
    severity=Severity.INFO,
):
    return Finding(
        id=finding_id,
        title="Test Finding",
        severity=severity,
        description="Test description",
        evidence="test evidence",
        recommendation="Test recommendation",
        url="https://example.com/",
        category="test",
    )


def test_build_scan_result():
    finding = make_finding()

    result = build_scan_result(
        target=make_target(),
        findings=[finding],
        pages_scanned=3,
        requests_made=7,
    )

    assert result.target.hostname == "example.com"
    assert result.pages_scanned == 3
    assert result.requests_made == 7
    assert result.finding_count == 1
    assert result.finished_at is not None
    assert result.findings[0].id == "test"


def test_build_scan_result_defaults():
    result = build_scan_result(
        target=make_target(),
        findings=[],
    )

    assert result.pages_scanned == 1
    assert result.requests_made == 1
    assert result.finding_count == 0
    assert result.finished_at is not None


def test_summarize_findings():
    findings = [
        make_finding("critical", Severity.CRITICAL),
        make_finding("high", Severity.HIGH),
        make_finding("medium", Severity.MEDIUM),
        make_finding("low", Severity.LOW),
        make_finding("info", Severity.INFO),
        make_finding("high-2", Severity.HIGH),
    ]

    summary = summarize_findings(findings)

    assert summary == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
        "INFO": 1,
    }


def test_summarize_empty_findings():
    summary = summarize_findings([])

    assert summary == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }


def test_save_json_report(tmp_path):
    result = build_scan_result(
        target=make_target(),
        findings=[
            make_finding("high", Severity.HIGH),
        ],
        pages_scanned=4,
        requests_made=9,
    )

    output = save_json_report(
        result,
        tmp_path,
    )

    assert output.exists()
    assert output.parent == tmp_path
    assert output.suffix == ".json"
    assert output.name.startswith("scan-example_com-")

    payload = json.loads(
        output.read_text(encoding="utf-8")
    )

    assert payload["target"]["hostname"] == "example.com"
    assert payload["pages_scanned"] == 4
    assert payload["requests_made"] == 9
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["id"] == "high"


def test_save_json_report_creates_directory(tmp_path):
    result = build_scan_result(
        target=make_target(),
        findings=[],
    )

    directory = tmp_path / "nested" / "reports"

    output = save_json_report(
        result,
        directory,
    )

    assert output.exists()
    assert output.parent == directory
