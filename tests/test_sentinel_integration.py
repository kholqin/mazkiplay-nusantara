import pytest

from app.sentinel.orchestrator import (
    run_sentinel,
)


@pytest.mark.asyncio
async def test_sentinel_without_http():
    result = await run_sentinel(
        "example.com",
        discover=False,
        observe_http=False,
    )

    assert result.target == (
        "https://example.com"
    )

    assert result.dns is not None
    assert result.finished_at is not None

    assert result.http_observations == []
    assert result.requests == 0


@pytest.mark.asyncio
async def test_sentinel_http_observation():
    result = await run_sentinel(
        "example.com",
        discover=False,
        observe_http=True,
    )

    assert result.http_observations

    observation = (
        result.http_observations[0]
    )

    assert observation.url.startswith(
        "https://example.com"
    )

    assert result.requests >= 1


@pytest.mark.asyncio
async def test_sentinel_result_contains_analysis_fields():
    result = await run_sentinel(
        "example.com",
        discover=False,
        observe_http=True,
    )

    assert result.http_observations
    assert result.fingerprints

    # Evidence dan findings boleh kosong jika response
    # target tidak menyediakan security headers.
    assert isinstance(result.evidence, list)
    assert isinstance(result.findings, list)


@pytest.mark.asyncio
async def test_sentinel_tls_observation():
    result = await run_sentinel(
        "example.com",
        discover=False,
        observe_http=False,
        inspect_tls=True,
    )

    assert result.tls_observations

    observation = (
        result.tls_observations[0]
    )

    assert observation.hostname == "example.com"
    assert observation.port == 443


@pytest.mark.asyncio
async def test_sentinel_tls_can_be_disabled():
    result = await run_sentinel(
        "example.com",
        discover=False,
        observe_http=False,
        inspect_tls=False,
    )

    assert result.tls_observations == []
