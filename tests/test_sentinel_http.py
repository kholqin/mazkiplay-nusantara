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


def test_observe_parses_structured_cookie_attributes():
    import httpx

    from app.sentinel.http import _cookie_observations

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    response = httpx.Response(
        200,
        request=request,
        headers=[
            (
                "set-cookie",
                "session=abc; Secure; HttpOnly; "
                "SameSite=Lax; Domain=example.com; Path=/",
            ),
        ],
    )

    cookies = _cookie_observations(response)

    assert len(cookies) == 1

    cookie = cookies[0]

    assert cookie.name == "session"
    assert cookie.value == "abc"
    assert cookie.secure is True
    assert cookie.httponly is True
    assert cookie.samesite == "lax"
    assert cookie.domain == "example.com"
    assert cookie.path == "/"


def test_observe_parses_multiple_set_cookie_headers():
    import httpx

    from app.sentinel.http import _cookie_observations

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    response = httpx.Response(
        200,
        request=request,
        headers=[
            (
                "set-cookie",
                "session=abc; Secure; HttpOnly; SameSite=Lax",
            ),
            (
                "set-cookie",
                "csrf=xyz; Secure; SameSite=Strict; Path=/",
            ),
        ],
    )

    cookies = _cookie_observations(response)

    assert len(cookies) == 2

    assert cookies[0].name == "session"
    assert cookies[0].secure is True
    assert cookies[0].httponly is True
    assert cookies[0].samesite == "lax"

    assert cookies[1].name == "csrf"
    assert cookies[1].secure is True
    assert cookies[1].httponly is False
    assert cookies[1].samesite == "strict"


def test_observe_ignores_malformed_set_cookie():
    import httpx

    from app.sentinel.http import _cookie_observations

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    response = httpx.Response(
        200,
        request=request,
        headers=[
            (
                "set-cookie",
                "malformed-cookie",
            ),
            (
                "set-cookie",
                "=missing-name",
            ),
            (
                "set-cookie",
                "valid=value; Secure",
            ),
        ],
    )

    cookies = _cookie_observations(response)

    assert len(cookies) == 1
    assert cookies[0].name == "valid"
    assert cookies[0].value == "value"
    assert cookies[0].secure is True
