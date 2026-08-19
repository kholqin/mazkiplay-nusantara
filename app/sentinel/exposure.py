from __future__ import annotations

from .models import ExposureReference


def generate_search_references(
    domain: str,
) -> list[ExposureReference]:

    queries = [
        (
            "documents",
            f"site:{domain} filetype:pdf",
            "Publicly indexed PDF documents.",
        ),
        (
            "documents",
            f"site:{domain} filetype:docx",
            "Publicly indexed DOCX documents.",
        ),
        (
            "api",
            f"site:{domain} inurl:api",
            "Potentially indexed API endpoints.",
        ),
        (
            "documentation",
            f"site:{domain} inurl:swagger",
            "Potential API documentation.",
        ),
        (
            "documentation",
            f"site:{domain} inurl:openapi",
            "Potential OpenAPI documentation.",
        ),
        (
            "configuration",
            f"site:{domain} filetype:xml",
            "Publicly indexed XML resources.",
        ),
        (
            "configuration",
            f"site:{domain} filetype:json",
            "Publicly indexed JSON resources.",
        ),
    ]

    return [
        ExposureReference(
            query=query,
            category=category,
            description=description,
        )
        for category, query, description in queries
    ]
