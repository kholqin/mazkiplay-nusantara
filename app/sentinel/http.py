from __future__ import annotations

import time
from urllib.parse import urljoin

import httpx

from .models import HTTPObservation


DEFAULT_TIMEOUT = 10.0


def _content_length(
    response: httpx.Response,
) -> int | None:
    value = response.headers.get("content-length")

    if value is not None:
        try:
            return int(value)
        except ValueError:
            pass

    try:
        return len(response.content)
    except Exception:
        return None


def _cookie_names(
    response: httpx.Response,
) -> list[str]:
    cookies: list[str] = []

    for cookie in response.headers.get_list("set-cookie"):
        name = cookie.split("=", 1)[0].strip()

        if name and name not in cookies:
            cookies.append(name)

    return cookies


def _normalized_headers(
    response: httpx.Response,
) -> dict[str, str]:
    return {
        key.lower(): value
        for key, value in response.headers.items()
    }


def _redirect_urls(
    response: httpx.Response,
) -> list[str]:
    redirects: list[str] = []

    for history in response.history:
        redirects.append(str(history.url))

        location = history.headers.get("location")

        if location:
            redirects.append(
                urljoin(
                    str(history.url),
                    location,
                )
            )

    if response.history:
        redirects.append(str(response.url))

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(redirects))


async def observe(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> HTTPObservation:
    """
    Perform one HTTP/HTTPS observation.

    This function collects evidence only. It does not attempt
    exploitation or mutate application state.
    """

    started = time.perf_counter()

    try:
        response = await client.get(
            url,
            timeout=timeout,
        )

        elapsed = (
            time.perf_counter() - started
        ) * 1000.0

        return HTTPObservation(
            url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            response_time_ms=round(
                elapsed,
                2,
            ),
            content_type=response.headers.get(
                "content-type"
            ),
            content_length=_content_length(
                response
            ),
            server=response.headers.get(
                "server"
            ),
            redirects=_redirect_urls(
                response
            ),
            headers=_normalized_headers(
                response
            ),
            cookies=_cookie_names(
                response
            ),
        )

    except httpx.HTTPError as exc:

        elapsed = (
            time.perf_counter() - started
        ) * 1000.0

        return HTTPObservation(
            url=url,
            response_time_ms=round(
                elapsed,
                2,
            ),
            error=(
                f"{type(exc).__name__}: {exc}"
            ),
        )

    except Exception as exc:

        elapsed = (
            time.perf_counter() - started
        ) * 1000.0

        return HTTPObservation(
            url=url,
            response_time_ms=round(
                elapsed,
                2,
            ),
            error=(
                f"{type(exc).__name__}: {exc}"
            ),
        )


async def observe_url(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    follow_redirects: bool = True,
    verify_tls: bool = True,
    user_agent: str = (
        "Mazkiplay-Nusantara-Sentinel/0.2"
    ),
) -> HTTPObservation:
    """
    Convenience wrapper for a standalone observation.
    """

    headers = {
        "User-Agent": user_agent,
        "Accept": "*/*",
    }

    async with httpx.AsyncClient(
        headers=headers,
        follow_redirects=follow_redirects,
        verify=verify_tls,
        timeout=timeout,
    ) as client:

        return await observe(
            client,
            url,
            timeout=timeout,
        )
