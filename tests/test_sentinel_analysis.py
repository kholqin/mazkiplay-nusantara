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


def test_missing_security_headers():
    from app.sentinel.analysis import (
        analyze_missing_security_headers,
    )
    from app.sentinel.models import HTTPObservation

    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        headers={
            "content-security-policy":
                "default-src 'self'",
        },
    )

    findings = analyze_missing_security_headers(
        observation
    )

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert (
        "header-missing:strict-transport-security"
        in ids
    )

    assert (
        "header-missing:x-frame-options"
        in ids
    )

    assert (
        "header-missing:content-security-policy"
        not in ids
    )


def test_missing_security_headers_are_info():
    from app.sentinel.analysis import (
        analyze_missing_security_headers,
    )
    from app.sentinel.models import HTTPObservation

    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        headers={},
    )

    findings = analyze_missing_security_headers(
        observation
    )

    assert findings

    assert all(
        finding.severity == "info"
        for finding in findings
    )

    assert all(
        finding.confidence == Confidence.HIGH
        for finding in findings
    )


def test_cookie_evidence_analysis():
    from app.sentinel.analysis import (
        analyze_cookie_evidence,
    )
    from app.sentinel.evidence import Evidence

    evidence = [
        Evidence(
            evidence_id="cookie:session",
            category="cookie",
            title="Observed HTTP cookie",
            value="session",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "cookie_name": "session",
            },
        )
    ]

    findings = analyze_cookie_evidence(
        evidence
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.finding_id == (
        "cookie-observed:cookie:session"
    )

    assert finding.category == "cookie"
    assert finding.severity == "info"
    assert finding.confidence == Confidence.HIGH
    assert finding.url == "https://example.com/"
    assert finding.metadata["analysis"] == (
        "observation-only"
    )


def test_cookie_analysis_ignores_other_evidence():
    from app.sentinel.analysis import (
        analyze_cookie_evidence,
    )
    from app.sentinel.evidence import Evidence

    evidence = [
        Evidence(
            evidence_id="header:csp",
            category="security-header",
            title="Content Security Policy",
            value="default-src 'self'",
        )
    ]

    assert analyze_cookie_evidence(
        evidence
    ) == []


def test_cookie_attribute_analysis_reports_missing_attributes():
    from app.sentinel.analysis import (
        analyze_cookie_attributes,
    )

    evidence = [
        Evidence(
            evidence_id="cookie:session",
            category="cookie",
            title="Observed HTTP cookie",
            value="abc",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "cookie_name": "session",
                "secure": "false",
                "httponly": "false",
                "samesite": "",
                "structured": "true",
            },
        )
    ]

    findings = analyze_cookie_attributes(evidence)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "cookie-secure-missing:cookie:session" in ids
    assert "cookie-httponly-missing:cookie:session" in ids
    assert "cookie-samesite-missing:cookie:session" in ids

    assert all(
        finding.severity == "info"
        for finding in findings
    )


def test_cookie_attribute_analysis_samesite_none_requires_secure():
    from app.sentinel.analysis import (
        analyze_cookie_attributes,
    )

    evidence = [
        Evidence(
            evidence_id="cookie:session",
            category="cookie",
            title="Observed HTTP cookie",
            value="abc",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "cookie_name": "session",
                "secure": "false",
                "httponly": "true",
                "samesite": "none",
                "structured": "true",
            },
        )
    ]

    findings = analyze_cookie_attributes(evidence)

    finding = next(
        item
        for item in findings
        if item.metadata.get("attribute")
        == "samesite-none"
    )

    assert finding.severity == "low"
    assert finding.confidence == Confidence.HIGH


def test_cookie_attribute_analysis_secure_cookie_is_clean():
    from app.sentinel.analysis import (
        analyze_cookie_attributes,
    )

    evidence = [
        Evidence(
            evidence_id="cookie:session",
            category="cookie",
            title="Observed HTTP cookie",
            value="abc",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "cookie_name": "session",
                "secure": "true",
                "httponly": "true",
                "samesite": "strict",
                "structured": "true",
            },
        )
    ]

    assert analyze_cookie_attributes(evidence) == []


def test_cookie_attribute_analysis_preserves_structured_evidence_id():
    from app.sentinel.analysis import (
        analyze_cookie_attributes,
    )
    from app.sentinel.evidence import Evidence

    evidence = [
        Evidence(
            evidence_id="cookie:0:session",
            category="cookie",
            title="Observed HTTP cookie",
            value="abc",
            url="https://example.com/",
            confidence="HIGH",
            metadata={
                "cookie_name": "session",
                "secure": "false",
                "httponly": "false",
                "samesite": "",
                "structured": "true",
            },
        )
    ]

    findings = analyze_cookie_attributes(evidence)

    assert findings

    assert all(
        finding.metadata["evidence_id"]
        == "cookie:0:session"
        for finding in findings
    )

    assert all(
        finding.metadata["cookie_name"]
        == "session"
        for finding in findings
    )


def test_structured_cookie_pipeline_produces_observation_and_attribute_findings():
    from app.sentinel.analysis import (
        analyze_cookie_attributes,
        analyze_cookie_evidence,
    )
    from app.sentinel.evidence import (
        collect_http_evidence,
    )
    from app.sentinel.models import (
        HTTPObservation,
        HTTPCookieObservation,
    )

    observation = HTTPObservation(
        url="https://example.com/",
        status_code=200,
        cookie_observations=[
            HTTPCookieObservation(
                name="session",
                value="abc",
                secure=False,
                httponly=False,
                samesite=None,
                domain="example.com",
                path="/",
            )
        ],
    )

    evidence = collect_http_evidence(
        observation
    )

    cookie_evidence = [
        item
        for item in evidence
        if item.category == "cookie"
    ]

    assert len(cookie_evidence) == 1

    cookie = cookie_evidence[0]

    assert cookie.evidence_id == "cookie:0:session"
    assert cookie.metadata["cookie_name"] == "session"
    assert cookie.metadata["structured"] == "true"
    assert cookie.metadata["domain"] == "example.com"
    assert cookie.metadata["path"] == "/"

    observation_findings = analyze_cookie_evidence(
        evidence
    )

    attribute_findings = analyze_cookie_attributes(
        evidence
    )

    assert len(observation_findings) == 1

    observation_finding = observation_findings[0]

    assert (
        observation_finding.finding_id
        == "cookie-observed:cookie:0:session"
    )

    attribute_ids = {
        finding.finding_id
        for finding in attribute_findings
    }

    assert (
        "cookie-secure-missing:cookie:0:session"
        in attribute_ids
    )

    assert (
        "cookie-httponly-missing:cookie:0:session"
        in attribute_ids
    )

    assert (
        "cookie-samesite-missing:cookie:0:session"
        in attribute_ids
    )
