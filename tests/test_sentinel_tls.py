from datetime import datetime, timedelta, timezone

from app.sentinel.analysis import analyze_tls
from app.sentinel.models import Confidence, TLSObservation


def test_tls_valid_certificate_info():
    now = datetime.now(timezone.utc)

    observation = TLSObservation(
        hostname="example.com",
        connected=True,
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        subject="commonName=example.com",
        issuer="commonName=Test CA",
        not_before=(
            now - timedelta(days=30)
        ).isoformat(),
        not_after=(
            now + timedelta(days=90)
        ).isoformat(),
        san=["example.com"],
        hostname_match=True,
        certificate_trusted=True,
    )

    findings = analyze_tls(observation)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "tls-certificate-info" in ids
    assert "tls-certificate-expired" not in ids
    assert "tls-hostname-mismatch" not in ids


def test_tls_expired_certificate():
    now = datetime.now(timezone.utc)

    observation = TLSObservation(
        hostname="example.com",
        connected=True,
        not_after=(
            now - timedelta(days=1)
        ).isoformat(),
        hostname_match=True,
    )

    findings = analyze_tls(observation)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "tls-certificate-expired" in ids


def test_tls_hostname_mismatch():
    observation = TLSObservation(
        hostname="example.com",
        connected=True,
        san=["other.example.com"],
        hostname_match=False,
    )

    findings = analyze_tls(observation)

    finding = next(
        item
        for item in findings
        if item.finding_id
        == "tls-hostname-mismatch"
    )

    assert finding.confidence == Confidence.HIGH
    assert finding.cwe == "CWE-297"


def test_tls_connection_error():
    observation = TLSObservation(
        hostname="example.com",
        connected=False,
        error="connection refused",
    )

    findings = analyze_tls(observation)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "tls-connection-error" in ids


def test_tls_wildcard_matches_single_label():
    observation = TLSObservation(
        hostname="api.example.com",
        connected=True,
        san=["*.example.com"],
        hostname_match=True,
    )

    findings = analyze_tls(observation)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "tls-hostname-mismatch" not in ids


def test_tls_wildcard_does_not_match_multiple_labels():
    observation = TLSObservation(
        hostname="api.dev.example.com",
        connected=True,
        san=["*.example.com"],
        hostname_match=False,
    )

    findings = analyze_tls(observation)

    ids = {
        finding.finding_id
        for finding in findings
    }

    assert "tls-hostname-mismatch" in ids
