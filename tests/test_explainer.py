"""Tests for the AI explanation module (fallback provider + fail-safe behavior)."""

from openaudit.ai.explainer import Explainer
from openaudit.ai.provider import FallbackProvider, LLMProvider, OpenAIProvider
from openaudit.utils.types import Finding, Severity


def _make_reentrancy_finding() -> Finding:
    return Finding(
        rule_id="reentrancy",
        title="Reentrancy Vulnerability",
        severity=Severity.HIGH,
        line=10,
        description="External call before state update",
        snippet='msg.sender.call{value: amount}("")',
    )


def test_fallback_provider_returns_explanation():
    provider = FallbackProvider()
    explanation = provider.explain(_make_reentrancy_finding())
    assert "Reentrancy" in explanation
    assert "Recommendation" in explanation or "pattern" in explanation.lower()


def test_explainer_uses_fallback_without_api_key(monkeypatch):
    monkeypatch.setattr("openaudit.config.OPENAI_API_KEY", None)
    explainer = Explainer(use_ai=True)
    assert isinstance(explainer.provider, FallbackProvider)


def test_explainer_uses_openai_with_api_key(monkeypatch):
    monkeypatch.setattr("openaudit.config.OPENAI_API_KEY", "sk-test-key")
    explainer = Explainer(use_ai=True)
    assert isinstance(explainer.provider, OpenAIProvider)


def test_explainer_respects_no_ai_flag(monkeypatch):
    monkeypatch.setattr("openaudit.config.OPENAI_API_KEY", "sk-test-key")
    explainer = Explainer(use_ai=False)
    assert isinstance(explainer.provider, FallbackProvider)


def test_explain_all():
    explainer = Explainer(provider=FallbackProvider())
    findings = [_make_reentrancy_finding(), _make_reentrancy_finding()]
    explanations = explainer.explain_all(findings)
    assert len(explanations) == 2
    assert 0 in explanations
    assert 1 in explanations


def test_explainer_catches_provider_error():
    """If the primary provider raises, the explainer falls back silently."""

    class BrokenProvider(LLMProvider):
        def explain(self, finding: Finding) -> str:
            raise RuntimeError("API is down")

    explainer = Explainer(provider=BrokenProvider())
    explanation = explainer.explain(_make_reentrancy_finding())
    assert "Reentrancy" in explanation
