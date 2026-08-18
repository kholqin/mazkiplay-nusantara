from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from app.models import Finding, Severity


async def check_tls(
    hostname: str,
    port: int = 443,
    timeout: float = 10.0,
) -> list[Finding]:
    """
    Inspect the TLS certificate presented by an HTTPS service.

    This performs a normal TLS connection and certificate inspection.
    """

    findings: list[Finding] = []

    try:
        certificate = await asyncio.wait_for(
            asyncio.to_thread(
                _fetch_certificate,
                hostname,
                port,
                timeout,
            ),
            timeout=timeout + 2,
        )
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        findings.append(
            Finding(
                id="tls-connection-error",
                title="TLS Connection Failed",
                severity=Severity.HIGH,
                description=(
                    f"The scanner could not establish a TLS connection "
                    f"to {hostname}:{port}."
                ),
                evidence=str(exc),
                recommendation=(
                    "Verify that the service supports HTTPS/TLS and "
                    "that the certificate configuration is valid."
                ),
                category="tls",
            )
        )
        return findings

    not_before = certificate["not_before"]
    not_after = certificate["not_after"]
    now = datetime.now(timezone.utc)

    if now < not_before:
        findings.append(
            Finding(
                id="tls-certificate-not-yet-valid",
                title="TLS Certificate Not Yet Valid",
                severity=Severity.HIGH,
                description=(
                    "The presented certificate is not valid yet."
                ),
                evidence=(
                    f"Valid from: {not_before.isoformat()}"
                ),
                recommendation=(
                    "Install a certificate whose validity period "
                    "includes the current time."
                ),
                category="tls",
            )
        )

    if now > not_after:
        findings.append(
            Finding(
                id="tls-certificate-expired",
                title="Expired TLS Certificate",
                severity=Severity.HIGH,
                description=(
                    "The presented TLS certificate has expired."
                ),
                evidence=(
                    f"Expired: {not_after.isoformat()}"
                ),
                recommendation=(
                    "Renew and deploy a valid TLS certificate."
                ),
                category="tls",
            )
        )

    remaining_seconds = (
        not_after - now
    ).total_seconds()

    remaining_days = int(
        remaining_seconds // 86_400
    )

    if 0 <= remaining_days <= 30:
        findings.append(
            Finding(
                id="tls-certificate-expiring-soon",
                title="TLS Certificate Expiring Soon",
                severity=Severity.MEDIUM,
                description=(
                    "The certificate expires within 30 days."
                ),
                evidence=(
                    f"Remaining validity: {remaining_days} days"
                ),
                recommendation=(
                    "Renew the certificate before expiration and "
                    "verify automatic renewal if available."
                ),
                category="tls",
                metadata={
                    "remaining_days": remaining_days,
                },
            )
        )

    findings.append(
        Finding(
            id="tls-certificate-info",
            title="TLS Certificate Information",
            severity=Severity.INFO,
            description=(
                "TLS certificate metadata was successfully collected."
            ),
            evidence=(
                f"Subject: {certificate['subject']}\n"
                f"Issuer: {certificate['issuer']}\n"
                f"Valid until: {not_after.isoformat()}"
            ),
            category="tls",
            metadata={
                "subject": certificate["subject"],
                "issuer": certificate["issuer"],
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "remaining_days": remaining_days,
            },
        )
    )

    return findings


def _fetch_certificate(
    hostname: str,
    port: int,
    timeout: float,
) -> dict:
    """
    Establish a standard TLS connection and return certificate metadata.
    """

    context = ssl.create_default_context()

    with socket.create_connection(
        (hostname, port),
        timeout=timeout,
    ) as raw_socket:

        with context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        ) as tls_socket:

            certificate = tls_socket.getpeercert()

            if not certificate:
                raise ssl.SSLError(
                    "The TLS server did not provide a certificate."
                )

            return {
                "subject": _flatten_name(
                    certificate.get("subject", ())
                ),
                "issuer": _flatten_name(
                    certificate.get("issuer", ())
                ),
                "not_before": _parse_certificate_date(
                    certificate["notBefore"]
                ),
                "not_after": _parse_certificate_date(
                    certificate["notAfter"]
                ),
            }


def _flatten_name(
    name: tuple,
) -> str:
    parts: list[str] = []

    for attribute_group in name:
        for key, value in attribute_group:
            parts.append(f"{key}={value}")

    return ", ".join(parts)


def _parse_certificate_date(
    value: str,
) -> datetime:
    return datetime.strptime(
        value,
        "%b %d %H:%M:%S %Y %Z",
    ).replace(tzinfo=timezone.utc)
