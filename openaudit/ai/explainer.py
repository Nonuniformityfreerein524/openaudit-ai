"""High-level explanation service — selects the right provider and generates explanations.

If the OpenAI API call fails for any reason (bad key, network error, model
not found) the explainer catches the exception and transparently falls back
to FallbackProvider so the tool never crashes because of AI issues.
"""

from __future__ import annotations

import logging

from openaudit import config
from openaudit.ai.provider import FallbackProvider, LLMProvider, OpenAIProvider
from openaudit.utils.types import Finding

logger = logging.getLogger(__name__)


class Explainer:
    """Generates AI explanations for vulnerability findings."""

    def __init__(self, provider: LLMProvider | None = None, use_ai: bool = True) -> None:
        if provider:
            self.provider = provider
        elif use_ai and config.has_api_key():
            self.provider = OpenAIProvider()
        else:
            self.provider = FallbackProvider()

        self._fallback = FallbackProvider()

    def explain(self, finding: Finding) -> str:
        """Return an explanation string for a single finding.

        If the primary provider raises, fall back to templates silently.
        """
        try:
            return self.provider.explain(finding)
        except Exception as exc:
            logger.warning("AI explanation failed (%s), using fallback", exc)
            return self._fallback.explain(finding)

    def explain_all(self, findings: list[Finding]) -> dict[int, str]:
        """Return a mapping of finding-index -> explanation for every finding."""
        return {i: self.explain(f) for i, f in enumerate(findings)}
