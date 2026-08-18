from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ScannerSettings(BaseModel):
    timeout: float = 10.0
    max_redirects: int = 5
    delay_between_requests: float = 0.5
    max_pages: int = 100
    user_agent: str = "Mazkiplay-Nusantara/0.1.0"


class CheckSettings(BaseModel):
    headers: bool = True
    cookies: bool = True
    tls: bool = True
    cors: bool = True
    csp: bool = True
    robots: bool = True
    sitemap: bool = True
    redirects: bool = True
    disclosure: bool = True


class OutputSettings(BaseModel):
    format: str = "json"
    directory: str = "reports"


class ProjectSettings(BaseModel):
    name: str = "Mazkiplay Nusantara"
    version: str = "0.1.0"
    description: str = "Web Security Assessment Toolkit"


class AppConfig(BaseModel):
    project: ProjectSettings = Field(default_factory=ProjectSettings)
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    checks: CheckSettings = Field(default_factory=CheckSettings)
    output: OutputSettings = Field(default_factory=OutputSettings)


def load_config(path: str | Path = "config.json") -> AppConfig:
    """
    Load scanner configuration from JSON.

    If the requested file does not exist, default settings are returned.
    """

    config_path = Path(path)

    if not config_path.exists():
        return AppConfig()

    with config_path.open("r", encoding="utf-8") as file:
        raw: dict[str, Any] = json.load(file)

    return AppConfig.model_validate(raw)


def save_config(config: AppConfig, path: str | Path) -> None:
    """Save configuration as formatted JSON."""

    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w", encoding="utf-8") as file:
        json.dump(
            config.model_dump(mode="json"),
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")
