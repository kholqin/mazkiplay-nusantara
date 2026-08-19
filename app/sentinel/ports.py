from __future__ import annotations

import asyncio

from .models import PortAsset


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


async def check_port(
    host: str,
    port: int,
    timeout: float = 1.5,
) -> PortAsset:

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        return PortAsset(
            host=host,
            port=port,
            state="open",
            service=COMMON_SERVICES.get(
                port,
                "unknown",
            ),
        )

    except (
        asyncio.TimeoutError,
        ConnectionRefusedError,
        OSError,
    ):

        return PortAsset(
            host=host,
            port=port,
            state="closed_or_filtered",
            service=COMMON_SERVICES.get(
                port,
                "unknown",
            ),
        )


async def scan_common_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 20,
) -> list[PortAsset]:

    ports = ports or list(
        COMMON_SERVICES.keys()
    )

    semaphore = asyncio.Semaphore(concurrency)

    async def worker(port: int):
        async with semaphore:
            return await check_port(
                host,
                port,
                timeout,
            )

    results = await asyncio.gather(
        *(worker(port) for port in ports)
    )

    return [
        result
        for result in results
        if result.state == "open"
    ]
