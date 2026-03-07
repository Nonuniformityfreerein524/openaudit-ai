"""Centralized configuration loaded from environment variables and .env file.

This module is the single source of truth for all runtime configuration.
Import `config` anywhere and read attributes directly — the .env file
is loaded once at import time.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None

OPENAI_BASE_URL: str | None = os.getenv("OPENAI_BASE_URL") or None

DEFAULT_MODEL = "gpt-5-mini"
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", DEFAULT_MODEL)

FALLBACK_MODEL = "gpt-4o-mini"


def has_api_key() -> bool:
    """Return True if an OpenAI API key is configured."""
    return bool(OPENAI_API_KEY)


def effective_base_url() -> str:
    """Return the base URL for display, falling back to the OpenAI default."""
    return OPENAI_BASE_URL or "https://api.openai.com/v1"
