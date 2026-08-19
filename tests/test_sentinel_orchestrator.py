import pytest

from app.sentinel.orchestrator import run_sentinel


@pytest.mark.asyncio
async def test_sentinel_example():
    result = await run_sentinel(
        "https://example.com",
        discover=False,
    )

    assert result.target.startswith(
        "https://"
    )

    assert result.dns is not None
    assert result.finished_at is not None


@pytest.mark.asyncio
async def test_sentinel_discovery():
    result = await run_sentinel(
        "https://example.com",
        discover=True,
    )

    assert result.hosts

    assert any(
        host.hostname == "example.com"
        for host in result.hosts
    )
