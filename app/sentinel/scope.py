from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


class Scope:
    """
    Authorization boundary for Sentinel.

    The scanner may operate on:
      - the explicitly supplied root hostname
      - its subdomains when allow_subdomains=True
    """

    def __init__(
        self,
        target: str,
        allow_subdomains: bool = True,
    ) -> None:

        target = target.strip()

        if "://" not in target:
            target = f"https://{target}"

        parsed = urlparse(target)

        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(
                "Only HTTP/HTTPS targets are supported."
            )

        if not parsed.hostname:
            raise ScopeError(
                "Target hostname is invalid."
            )

        self.target = target
        self.scheme = parsed.scheme
        self.hostname = (
            parsed.hostname
            .lower()
            .rstrip(".")
        )
        self.allow_subdomains = allow_subdomains

    def contains(
        self,
        hostname: str,
    ) -> bool:

        hostname = (
            hostname
            .strip()
            .lower()
            .rstrip(".")
        )

        if hostname == self.hostname:
            return True

        if not self.allow_subdomains:
            return False

        return hostname.endswith(
            f".{self.hostname}"
        )

    def validate(
        self,
        hostname: str,
    ) -> str:

        if not self.contains(hostname):
            raise ScopeError(
                f"Out-of-scope host: {hostname}"
            )

        return hostname

    def __repr__(self) -> str:
        return (
            f"Scope("
            f"hostname={self.hostname!r}, "
            f"allow_subdomains="
            f"{self.allow_subdomains!r}"
            f")"
        )
