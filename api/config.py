"""Shared PAN-API credential configuration loading."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def panapi_config_path() -> Path:
    """Return the PAN-API config path, honoring an optional explicit override."""
    return Path(os.path.expanduser(os.environ.get("PANAPI_CONFIG", "~/.panapi/config.yml")))


def load_panapi_config() -> dict[str, Any]:
    """Load credentials and endpoint settings from the user's PAN-API config."""
    path = panapi_config_path()
    with path.open("r", encoding="utf-8") as config_file:
        config = yaml.safe_load(config_file) or {}
    if not isinstance(config, dict):
        raise ValueError(f"PAN-API config must contain a YAML mapping: {path}")
    return config
