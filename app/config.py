from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


APP_NAME = "Mazkiplay Nusantara"
APP_VERSION = "0.1.0"


def _env_bool(
    name: str,
    default: bool,
) -> bool:
    value = os.getenv(name)

    if value is None:
        return default

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_int(
    name: str,
    default: int,
    minimum: int = 0,
) -> int:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed = int(value)
    except ValueError:
        return default

    return max(
        parsed,
        minimum,
    )


def _env_float(
    name: str,
    default: float,
    minimum: float = 0.0,
) -> float:
    value = os.getenv(name)

    if value is None:
        return default

    try:
        parsed = float(value)
    except ValueError:
        return default

    return max(
        parsed,
        minimum,
    )


@dataclass(slots=True)
class ScannerConfig:
    """
    Runtime configuration for Mazkiplay Nusantara.
    """

    timeout: float = 10.0

    connect_timeout: float = 5.0

    read_timeout: float = 10.0

    write_timeout: float = 10.0

    pool_timeout: float = 5.0

    follow_redirects: bool = True

    max_redirects: int = 5

    max_pages: int = 100

    max_sitemap_urls: int = 100

    concurrency: int = 5

    request_delay: float = 0.25

    user_agent: str = (
        "Mazkiplay-Nusantara/"
        f"{APP_VERSION} "
        "(Security Assessment)"
    )

    verify_tls: bool = True

    allow_external_redirects: bool = False

    reports_dir: Path = Path("reports")

    enable_headers: bool = True

    enable_cookies: bool = True

    enable_cors: bool = True

    enable_csp: bool = True

    enable_disclosure: bool = True

    enable_redirects: bool = True

    enable_robots: bool = True

    enable_sitemap: bool = True

    enable_crawler: bool = True


def load_config() -> ScannerConfig:
    """
    Load scanner configuration from environment variables.

    Environment variables are optional. Defaults are used when
    variables are absent or invalid.
    """

    reports_dir = Path(
        os.getenv(
            "MNP_REPORTS_DIR",
            "reports",
        )
    )

    return ScannerConfig(

        timeout=_env_float(
            "MNP_TIMEOUT",
            10.0,
            minimum=0.5,
        ),

        connect_timeout=_env_float(
            "MNP_CONNECT_TIMEOUT",
            5.0,
            minimum=0.5,
        ),

        read_timeout=_env_float(
            "MNP_READ_TIMEOUT",
            10.0,
            minimum=0.5,
        ),

        write_timeout=_env_float(
            "MNP_WRITE_TIMEOUT",
            10.0,
            minimum=0.5,
        ),

        pool_timeout=_env_float(
            "MNP_POOL_TIMEOUT",
            5.0,
            minimum=0.5,
        ),

        follow_redirects=_env_bool(
            "MNP_FOLLOW_REDIRECTS",
            True,
        ),

        max_redirects=_env_int(
            "MNP_MAX_REDIRECTS",
            5,
            minimum=0,
        ),

        max_pages=_env_int(
            "MNP_MAX_PAGES",
            100,
            minimum=1,
        ),

        max_sitemap_urls=_env_int(
            "MNP_MAX_SITEMAP_URLS",
            100,
            minimum=1,
        ),

        concurrency=_env_int(
            "MNP_CONCURRENCY",
            5,
            minimum=1,
        ),

        request_delay=_env_float(
            "MNP_REQUEST_DELAY",
            0.25,
            minimum=0.0,
        ),

        user_agent=os.getenv(
            "MNP_USER_AGENT",
            (
                "Mazkiplay-Nusantara/"
                f"{APP_VERSION} "
                "(Security Assessment)"
            ),
        ),

        verify_tls=_env_bool(
            "MNP_VERIFY_TLS",
            True,
        ),

        allow_external_redirects=_env_bool(
            "MNP_ALLOW_EXTERNAL_REDIRECTS",
            False,
        ),

        reports_dir=reports_dir,

        enable_headers=_env_bool(
            "MNP_CHECK_HEADERS",
            True,
        ),

        enable_cookies=_env_bool(
            "MNP_CHECK_COOKIES",
            True,
        ),

        enable_cors=_env_bool(
            "MNP_CHECK_CORS",
            True,
        ),

        enable_csp=_env_bool(
            "MNP_CHECK_CSP",
            True,
        ),

        enable_disclosure=_env_bool(
            "MNP_CHECK_DISCLOSURE",
            True,
        ),

        enable_redirects=_env_bool(
            "MNP_CHECK_REDIRECTS",
            True,
        ),

        enable_robots=_env_bool(
            "MNP_CHECK_ROBOTS",
            True,
        ),

        enable_sitemap=_env_bool(
            "MNP_CHECK_SITEMAP",
            True,
        ),

        enable_crawler=_env_bool(
            "MNP_CHECK_CRAWLER",
            True,
        ),
    )
