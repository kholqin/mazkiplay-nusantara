from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from .models import TLSObservation


def _flatten_name(name: tuple) -> str:
    parts: list[str] = []

    for attribute_group in name:
        for key, value in attribute_group:
            parts.append(f"{key}={value}")

    return ", ".join(parts)


def _parse_certificate_date(value: str) -> datetime:
    return datetime.strptime(
        value,
        "%b %d %H:%M:%S %Y %Z",
    ).replace(tzinfo=timezone.utc)


def _certificate_names(certificate: dict) -> list[str]:
    names: list[str] = []

    for item in certificate.get("subjectAltName", ()):
        if len(item) == 2 and item[0].lower() == "dns":
            names.append(item[1])

    return names


def _hostname_matches(
    hostname: str,
    certificate: dict,
) -> bool:
    """
    Check whether hostname matches the certificate SAN/CN.

    Python 3.14 no longer exposes ssl.match_hostname(),
    so this function uses the certificate names directly.
    Wildcards are accepted only for a complete left-most
    DNS label, e.g. *.example.com.
    """

    hostname = hostname.rstrip(".").lower()

    names = _certificate_names(certificate)

    if not names:
        subject = certificate.get("subject", ())

        for group in subject:
            for key, value in group:
                if key == "commonName":
                    names.append(value)

    for name in names:
        name = str(name).rstrip(".").lower()

        if name == hostname:
            return True

        if name.startswith("*."):
            suffix = name[1:]

            # Wildcard must match exactly one DNS label.
            if hostname.endswith(suffix):
                prefix = hostname[: -len(suffix)]

                if prefix and "." not in prefix.rstrip("."):
                    return True

    return False


def _fetch_tls(
    hostname: str,
    port: int,
    timeout: float,
) -> TLSObservation:

    observation = TLSObservation(
        hostname=hostname,
        port=port,
    )

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
                    "TLS server did not provide a certificate."
                )

            observation.connected = True

            observation.tls_version = (
                tls_socket.version()
            )

            cipher = tls_socket.cipher()

            if cipher:
                observation.cipher = cipher[0]

            observation.subject = _flatten_name(
                certificate.get("subject", ())
            )

            observation.issuer = _flatten_name(
                certificate.get("issuer", ())
            )

            observation.serial_number = (
                certificate.get("serialNumber")
            )

            if certificate.get("notBefore"):
                observation.not_before = (
                    _parse_certificate_date(
                        certificate["notBefore"]
                    ).isoformat()
                )

            if certificate.get("notAfter"):
                observation.not_after = (
                    _parse_certificate_date(
                        certificate["notAfter"]
                    ).isoformat()
                )

            observation.san = _certificate_names(
                certificate
            )

            observation.hostname_match = (
                _hostname_matches(
                    hostname,
                    certificate,
                )
            )

            observation.certificate_trusted = True

            return observation


async def observe_tls(
    hostname: str,
    *,
    port: int = 443,
    timeout: float = 10.0,
) -> TLSObservation:

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(
                _fetch_tls,
                hostname,
                port,
                timeout,
            ),
            timeout=timeout + 2,
        )

    except (
        OSError,
        ssl.SSLError,
        asyncio.TimeoutError,
    ) as exc:

        return TLSObservation(
            hostname=hostname,
            port=port,
            connected=False,
            certificate_trusted=False,
            error=str(exc),
        )
