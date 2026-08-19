from app.sentinel.assets import (
    classify_url,
    extract_assets,
    extract_references,
    normalize_url,
)
from app.sentinel.scope import Scope


def test_normalize_relative_url():
    result = normalize_url(
        "https://example.com/page/",
        "/static/app.js#main",
    )

    assert result == (
        "https://example.com/static/app.js"
    )


def test_normalize_rejects_non_http():
    assert normalize_url(
        "https://example.com/",
        "javascript:alert(1)",
    ) is None

    assert normalize_url(
        "https://example.com/",
        "mailto:test@example.com",
    ) is None


def test_classify_url():
    assert (
        classify_url("https://example.com/app.js")
        == "javascript"
    )

    assert (
        classify_url("https://example.com/style.css")
        == "css"
    )

    assert (
        classify_url("https://example.com/data.json")
        == "json"
    )

    assert (
        classify_url("https://example.com/logo.png")
        == "image"
    )


def test_extract_references():
    html = """
    <html>
      <a href="/login">Login</a>
      <script src="/static/app.js"></script>
      <link href="/static/style.css" rel="stylesheet">
      <img src="/images/logo.png">
      <a href="https://external.example/path">External</a>
    </html>
    """

    references = extract_references(
        html,
        "https://example.com/",
    )

    urls = {
        url
        for url, _ in references
    }

    assert (
        "https://example.com/login"
        in urls
    )

    assert (
        "https://example.com/static/app.js"
        in urls
    )

    assert (
        "https://example.com/static/style.css"
        in urls
    )

    assert (
        "https://example.com/images/logo.png"
        in urls
    )

    assert (
        "https://external.example/path"
        in urls
    )


def test_extract_assets_respects_scope():
    scope = Scope(
        "https://example.com"
    )

    html = """
    <script src="/app.js"></script>
    <img src="/logo.png">
    <script src="https://cdn.example.net/app.js"></script>
    """

    assets = extract_assets(
        html,
        "https://example.com/",
        scope,
    )

    urls = {
        asset.url
        for asset in assets
    }

    assert (
        "https://example.com/app.js"
        in urls
    )

    assert (
        "https://example.com/logo.png"
        in urls
    )

    assert not any(
        "cdn.example.net" in url
        for url in urls
    )


def test_asset_metadata():
    scope = Scope(
        "https://example.com"
    )

    html = """
    <script src="/static/app.js"></script>
    """

    assets = extract_assets(
        html,
        "https://example.com/index",
        scope,
    )

    assert len(assets) == 1

    asset = assets[0]

    assert asset.asset_type == "javascript"
    assert asset.source == "html"
    assert asset.parent_url == (
        "https://example.com/index"
    )
    assert asset.discovered_from == (
        "example.com"
    )
