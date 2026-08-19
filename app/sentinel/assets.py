from __future__ import annotations

from urllib.parse import urlparse

from .models import WebAsset


CONTENT_TYPES = {
    "text/html": "html",
    "text/css": "css",
    "javascript": "javascript",
    "json": "json",
    "xml": "xml",
    "image/": "image",
    "font/": "font",
}


def classify_content_type(
    content_type: str | None,
) -> str:

    if not content_type:
        return "unknown"

    value = content_type.lower()

    for marker, asset_type in CONTENT_TYPES.items():
        if marker in value:
            return asset_type

    return "other"


def make_asset(
    url: str,
    status_code: int | None,
    content_type: str | None,
    size: int | None = None,
    source: str | None = None,
) -> WebAsset:

    return WebAsset(
        url=url,
        asset_type=classify_content_type(
            content_type
        ),
        status_code=status_code,
        content_type=content_type,
        size=size,
        source=source,
    )
