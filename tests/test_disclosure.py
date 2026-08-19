import httpx

from modules.disclosure import check_disclosure, _deduplicate_findings
from app.models import Finding, Severity


def make_response(
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        200,
        headers=headers or {},
        request=httpx.Request(
            "GET",
            "https://example.com/",
        ),
    )


def test_no_disclosure_returns_no_findings():
    response = make_response(
        {
            "content-type": "text/html",
        }
    )

    findings = check_disclosure(response)

    assert findings == []


def test_disclosure_headers():
    response = make_response(
        {
            "Server": "Apache",
            "X-Powered-By": "PHP",
            "X-AspNet-Version": "4.8",
            "X-Generator": "WordPress",
        }
    )

    findings = check_disclosure(response)

    ids = {finding.id for finding in findings}

    assert "disclosure-server" in ids
    assert "disclosure-x_powered_by" in ids
    assert "disclosure-x_aspnet_version" in ids
    assert "disclosure-x_generator" in ids


def test_disclosure_finding_metadata():
    response = make_response(
        {
            "Server": "nginx",
        }
    )

    findings = check_disclosure(response)

    finding = next(
        item for item in findings
        if item.id == "disclosure-server"
    )

    assert finding.severity == Severity.LOW
    assert finding.category == "information-disclosure"
    assert finding.metadata["header"] == "Server"
    assert finding.metadata["value"] == "nginx"


def test_technology_version_disclosure():
    response = make_response(
        {
            "Server": "Apache/2.4.62",
            "X-Runtime": "Express 4.21.2",
        }
    )

    findings = check_disclosure(response)

    ids = {finding.id for finding in findings}

    assert "disclosure-server" in ids
    assert "technology-version-server" in ids
    assert "technology-version-x_runtime" in ids


def test_version_disclosure_metadata():
    response = make_response(
        {
            "Server": "nginx/1.27.1",
        }
    )

    findings = check_disclosure(response)

    finding = next(
        item for item in findings
        if item.id == "technology-version-server"
    )

    assert finding.severity == Severity.INFO
    assert finding.category == "information-disclosure"
    assert finding.metadata["header"] == "server"
    assert finding.metadata["matches"]


def test_headers_without_version_are_ignored():
    response = make_response(
        {
            "Server": "production",
            "X-Powered-By": "internal-service",
        }
    )

    findings = check_disclosure(response)

    ids = {finding.id for finding in findings}

    assert "technology-version-server" not in ids
    assert "technology-version-x_powered_by" not in ids


def test_duplicate_findings_are_removed():
    finding = Finding(
        id="test-finding",
        title="Test",
        severity=Severity.INFO,
        description="Test finding",
        evidence="Server: nginx/1.27.1",
        recommendation="Test recommendation",
        url="https://example.com/",
        category="information-disclosure",
    )

    findings = _deduplicate_findings(
        [finding, finding]
    )

    assert len(findings) == 1
    assert findings[0].id == "test-finding"
