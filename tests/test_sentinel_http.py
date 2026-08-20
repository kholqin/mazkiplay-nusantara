import httpx
import pytest

from app.sentinel.http import observe
from app.sentinel.models import HTTPObservation


def make_response(
    url="https://example.com/",
    status_code=200,
    headers=None,
):
    return httpx.Response(
        status_code,
        headers=headers or {},
        request=httpx.Request(
            "GET",
            url,
        ),
    )


@pytest.mark.asyncio
async def test_http_observation_basic(monkeypatch):

    transport = httpx.MockTransport(
        lambda request: make_response(
            url=str(request.url),
            headers={
                "content-type": "text/html",
                "content-length": "42",
                "server": "test-server",
                "x-test": "value",
                "set-cookie": (
                    "session=abc; Secure; HttpOnly"
                ),
            },
        )
    )

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=True,
    ) as client:

        result = await observe(
            client,
            "https://example.com/",
        )

    assert isinstance(
        result,
        HTTPObservation,
    )

    assert result.status_code == 200

    assert result.final_url == (
        "https://example.com/"
    )

    assert result.content_type == (
        "text/html"
    )

    assert result.content_length == 42

    assert result.server == "test-server"

    assert result.headers["x-test"] == "value"

    assert "session" in result.cookies

    assert result.error is None


@pytest.mark.asyncio
async def test_http_observation_error():

    transport = httpx.MockTransport(
        lambda request: (
            httpx.Response(
                503,
                request=request,
            )
        )
    )

    async with httpx.AsyncClient(
        transport=transport,
    ) as client:

        result = await observe(
            client,
            "https://example.com/",
        )

    assert result.status_code == 503

    assert result.error is None


@pytest.mark.asyncio
async def test_http_observation_network_error():

    async def handler(request):
        raise httpx.ConnectError(
            "connection failed",
            request=request,
        )

    transport = httpx.MockTransport(
        handler
    )

    async with httpx.AsyncClient(
        transport=transport,
    ) as client:

        result = await observe(
            client,
            "https://example.com/",
        )

    assert result.status_code is None

    assert result.error is not None

    assert "ConnectError" in result.error


@pytest.mark.asyncio
async def test_http_cookie_observation_attributes():

    transport = httpx.MockTransport(
        lambda request: make_response(
            url=str(request.url),
            headers={
                "set-cookie": (
                    "session=abc; "
                    "Secure; HttpOnly; "
                    "SameSite=Lax; "
                    "Path=/; "
                    "Domain=example.com"
                ),
            },
        )
    )

    async with httpx.AsyncClient(
        transport=transport,
    ) as client:

        result = await observe(
            client,
            "https://example.com/",
        )

    assert "session" in result.cookies

    assert len(
        result.cookie_observations
    ) == 1

    cookie = result.cookie_observations[0]

    assert cookie.name == "session"
    assert cookie.value == "abc"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    assert cookie.path == "/"
    assert cookie.domain == "example.com"
