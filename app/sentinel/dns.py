from __future__ import annotations

import socket

from .models import DNSProfile


def resolve_host(hostname: str) -> list[str]:
    addresses: set[str] = set()

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for result in results:
            address = result[4][0]
            addresses.add(address)

    except OSError:
        pass

    return sorted(addresses)


def collect_dns_profile(
    hostname: str,
) -> DNSProfile:

    profile = DNSProfile()

    for address in resolve_host(hostname):
        if ":" in address:
            profile.aaaa.append(address)
        else:
            profile.a.append(address)

    try:
        canonical = socket.getfqdn(hostname)

        if (
            canonical
            and canonical.lower() != hostname.lower()
        ):
            profile.cname.append(canonical)

    except OSError:
        pass

    return profile

