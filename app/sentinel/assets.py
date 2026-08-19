from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

from .models import WebAsset
from .scope import Scope


ASSET_ATTRIBUTES = {
    "script": ("src", "javascript"),
    "link": ("href", "resource"),
    "img": ("src", "image"),
    "iframe": ("src", "iframe"),
    "source": ("src", "media"),
    "video": ("src", "media"),
    "audio": ("src", "media"),
    "form": ("action", "form"),
}


def normalize_url(
    base_url: str,
    value: str,
) -> str | None:
    value = value.strip()

    if not value:
        return None

    if value.startswith(
        (
            "#",
            "javascript:",
            "mailto:",
            "tel:",
            "data:",
            "blob:",
        )
    ):
        return None

    absolute = urljoin(base_url, value)
    absolute, _ = urldefrag(absolute)

    parsed = urlparse(absolute)

    if parsed.scheme not in {"http", "https"}:
        return None

    if not parsed.hostname:
        return None

    return absolute


def classify_url(url: str) -> str:
    path = urlparse(url).path.lower()

    if path.endswith((".js", ".mjs")):
        return "javascript"

    if path.endswith(".css"):
        return "css"

    if path.endswith(".json"):
        return "json"

    if path.endswith((".xml", ".rss", ".atom")):
        return "xml"

    if path.endswith(
        (
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".svg",
            ".ico",
        )
    ):
        return "image"

    if path.endswith(
        (
            ".woff",
            ".woff2",
            ".ttf",
            ".otf",
        )
    ):
        return "font"

    if path.endswith(
        (
            ".mp4",
            ".webm",
            ".mp3",
            ".wav",
        )
    ):
        return "media"

    return "resource"


class AssetParser(HTMLParser):
    """
    Extract URL-bearing HTML references.

    Parsing only. No network requests are performed here.
    """

    def __init__(
        self,
        base_url: str,
    ) -> None:
        super().__init__(
            convert_charrefs=True
        )

        self.base_url = base_url

        self.references: list[
            tuple[str, str]
        ] = []

    def handle_starttag(
        self,
        tag: str,
        attrs,
    ) -> None:
        tag = tag.lower()

        if tag == "a":
            attribute = "href"
            asset_type = "page"

        elif tag in ASSET_ATTRIBUTES:
            attribute, asset_type = ASSET_ATTRIBUTES[tag]

        else:
            return

        attributes = dict(attrs)

        value = attributes.get(attribute)

        if not value:
            return

        normalized = normalize_url(
            self.base_url,
            value,
        )

        if normalized:
            self.references.append(
                (
                    normalized,
                    asset_type,
                )
            )


def extract_references(
    html: str,
    base_url: str,
) -> list[tuple[str, str]]:
    parser = AssetParser(base_url)

    parser.feed(html)

    return list(
        dict.fromkeys(
            parser.references
        )
    )


def extract_assets(
    html: str,
    page_url: str,
    scope: Scope,
) -> list[WebAsset]:
    """
    Convert HTML references into scoped WebAsset records.

    External resources are excluded from the inventory.
    """

    assets: list[WebAsset] = []

    references = extract_references(
        html,
        page_url,
    )

    page_host = urlparse(page_url).hostname

    for url, reference_type in references:
        parsed = urlparse(url)

        if not parsed.hostname:
            continue

        if not scope.contains(parsed.hostname):
            continue

        asset_type = (
            "page"
            if reference_type == "page"
            else (
                reference_type
                if reference_type in {
                    "javascript",
                    "image",
                    "iframe",
                    "media",
                    "form",
                }
                else classify_url(url)
            )
        )

        assets.append(
            WebAsset(
                url=url,
                asset_type=asset_type,
                source="html",
                parent_url=page_url,
                discovered_from=page_host,
            )
        )

    return assets
