from app.sentinel.analysis import analyze_evidence
from app.sentinel.evidence import Evidence
from app.sentinel.models import Confidence


def test_security_header_analysis():
    evidence = [
        Evidence(
            evidence_id="header:content-security-policy",
            category="security-header",
            title="Content Security Policy",
            value="default-src 'self'",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "header": "content-security-policy",
            },
        )
    ]

    findings = analyze_evidence(evidence)

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.finding_id
        == "header-present:header:content-security-policy"
    )

    assert finding.category == "security-header"
    assert finding.severity == "info"
    assert finding.confidence == Confidence.HIGH
    assert finding.url == "https://example.com/"


def test_non_security_evidence_produces_no_finding():
    evidence = [
        Evidence(
            evidence_id="server-header",
            category="technology",
            title="Observed server header",
            value="nginx",
        )
    ]

    assert analyze_evidence(evidence) == []
