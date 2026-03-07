"""Tests for the centralized configuration module."""

from openaudit import config


def test_config_has_model():
    assert isinstance(config.OPENAI_MODEL, str)
    assert len(config.OPENAI_MODEL) > 0


def test_config_fallback_model_defined():
    assert config.FALLBACK_MODEL == "gpt-4o-mini"


def test_has_api_key_reflects_config(monkeypatch):
    monkeypatch.setattr(config, "OPENAI_API_KEY", "sk-test")
    assert config.has_api_key() is True

    monkeypatch.setattr(config, "OPENAI_API_KEY", None)
    assert config.has_api_key() is False


def test_effective_base_url_default(monkeypatch):
    monkeypatch.setattr(config, "OPENAI_BASE_URL", None)
    assert config.effective_base_url() == "https://api.openai.com/v1"


def test_effective_base_url_custom(monkeypatch):
    monkeypatch.setattr(config, "OPENAI_BASE_URL", "https://my-proxy.example.com/v1")
    assert config.effective_base_url() == "https://my-proxy.example.com/v1"
