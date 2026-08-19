import asyncio
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from modules.tls import (
    _fetch_certificate,
    _flatten_name,
    _parse_certificate_date,
    check_tls,
)


def make_certificate(
    *,
    not_before: datetime,
    not_after: datetime,
    subject: str = "CN=example.com",
    issuer: str = "CN=Test CA",
) -> dict:
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
    }


@pytest.mark.asyncio
async def test_tls_connection_error(monkeypatch):
    def raise_error(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(
        "modules.tls._fetch_certificate",
        raise_error,
    )

    findings = await check_tls(
        "example.com",
        timeout=1,
    )

    ids = {finding.id for finding in findings}

    assert "tls-connection-error" in ids


@pytest.mark.asyncio
async def test_tls_timeout(monkeypatch):
    async def fake_wait_for(awaitable, *args, **kwargs):
        awaitable.close()
        raise asyncio.TimeoutError()

    monkeypatch.setattr(
        "modules.tls.asyncio.wait_for",
        fake_wait_for,
    )

    findings = await check_tls(
        "example.com",
        timeout=1,
    )

    ids = {finding.id for finding in findings}

    assert "tls-connection-error" in ids


@pytest.mark.asyncio
async def test_certificate_not_yet_valid(monkeypatch):
    now = datetime.now(timezone.utc)

    certificate = make_certificate(
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=90),
    )

    async def fake_to_thread(*args, **kwargs):
        return certificate

    monkeypatch.setattr(
        "modules.tls.asyncio.to_thread",
        fake_to_thread,
    )

    findings = await check_tls("example.com")

    ids = {finding.id for finding in findings}

    assert "tls-certificate-not-yet-valid" in ids
    assert "tls-certificate-info" in ids


@pytest.mark.asyncio
async def test_certificate_expired(monkeypatch):
    now = datetime.now(timezone.utc)

    certificate = make_certificate(
        not_before=now - timedelta(days=180),
        not_after=now - timedelta(days=1),
    )

    async def fake_to_thread(*args, **kwargs):
        return certificate

    monkeypatch.setattr(
        "modules.tls.asyncio.to_thread",
        fake_to_thread,
    )

    findings = await check_tls("example.com")

    ids = {finding.id for finding in findings}

    assert "tls-certificate-expired" in ids
    assert "tls-certificate-info" in ids


@pytest.mark.asyncio
async def test_certificate_expiring_soon(monkeypatch):
    now = datetime.now(timezone.utc)

    certificate = make_certificate(
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=10),
    )

    async def fake_to_thread(*args, **kwargs):
        return certificate

    monkeypatch.setattr(
        "modules.tls.asyncio.to_thread",
        fake_to_thread,
    )

    findings = await check_tls("example.com")

    ids = {finding.id for finding in findings}

    assert "tls-certificate-expiring-soon" in ids
    assert "tls-certificate-info" in ids

    expiring = next(
        finding
        for finding in findings
        if finding.id == "tls-certificate-expiring-soon"
    )

    assert expiring.metadata["remaining_days"] in {9, 10}


@pytest.mark.asyncio
async def test_valid_certificate(monkeypatch):
    now = datetime.now(timezone.utc)

    certificate = make_certificate(
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=90),
    )

    async def fake_to_thread(*args, **kwargs):
        return certificate

    monkeypatch.setattr(
        "modules.tls.asyncio.to_thread",
        fake_to_thread,
    )

    findings = await check_tls("example.com")

    ids = {finding.id for finding in findings}

    assert "tls-certificate-info" in ids
    assert "tls-certificate-expired" not in ids
    assert "tls-certificate-not-yet-valid" not in ids
    assert "tls-certificate-expiring-soon" not in ids


def test_flatten_name():
    name = (
        (
            ("commonName", "example.com"),
        ),
        (
            ("organizationName", "Example"),
        ),
    )

    result = _flatten_name(name)

    assert result == (
        "commonName=example.com, "
        "organizationName=Example"
    )


def test_flatten_empty_name():
    assert _flatten_name(()) == ""


def test_parse_certificate_date():
    result = _parse_certificate_date(
        "Aug 19 12:00:00 2026 GMT"
    )

    assert result == datetime(
        2026,
        8,
        19,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )


def test_parse_certificate_date_is_utc():
    result = _parse_certificate_date(
        "Jan 01 00:00:00 2026 GMT"
    )

    assert result.tzinfo == timezone.utc


def test_parse_certificate_date_invalid():
    with pytest.raises(ValueError):
        _parse_certificate_date(
            "not-a-certificate-date"
        )


def test_fetch_certificate_empty_certificate(monkeypatch):
    class FakeTLSContext:
        def wrap_socket(self, raw_socket, server_hostname):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def getpeercert(self):
            return {}

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        "modules.tls.ssl.create_default_context",
        lambda: FakeTLSContext(),
    )

    monkeypatch.setattr(
        "modules.tls.socket.create_connection",
        lambda *args, **kwargs: FakeRawSocket(),
    )

    with pytest.raises(ssl.SSLError):
        _fetch_certificate(
            "example.com",
            443,
            1,
        )


def test_fetch_certificate_metadata(monkeypatch):
    class FakeTLSContext:
        def wrap_socket(self, raw_socket, server_hostname):
            return self

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def getpeercert(self):
            return {
                "subject": (
                    (("commonName", "example.com"),),
                ),
                "issuer": (
                    (("commonName", "Test CA"),),
                ),
                "notBefore": "Aug 01 00:00:00 2026 GMT",
                "notAfter": "Aug 01 00:00:00 2027 GMT",
            }

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        "modules.tls.ssl.create_default_context",
        lambda: FakeTLSContext(),
    )

    monkeypatch.setattr(
        "modules.tls.socket.create_connection",
        lambda *args, **kwargs: FakeRawSocket(),
    )

    certificate = _fetch_certificate(
        "example.com",
        443,
        1,
    )

    assert certificate["subject"] == "commonName=example.com"
    assert certificate["issuer"] == "commonName=Test CA"
    assert certificate["not_before"].year == 2026
    assert certificate["not_after"].year == 2027
