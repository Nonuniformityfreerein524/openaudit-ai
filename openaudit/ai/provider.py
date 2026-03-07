"""LLM provider abstraction — swap models without touching the rest of the codebase."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from openaudit import config
from openaudit.ai.prompts import SYSTEM_PROMPT, build_finding_prompt
from openaudit.utils.types import Finding

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Interface that any LLM backend must implement."""

    @abstractmethod
    def explain(self, finding: Finding) -> str:
        """Generate a human-readable explanation for a vulnerability finding."""


class OpenAIProvider(LLMProvider):
    """OpenAI GPT-based explanation provider.

    Reads defaults from `config` but accepts overrides for model / key / base_url
    so the CLI `--model` flag and tests can inject values.
    """

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model or config.OPENAI_MODEL
        self.api_key = api_key or config.OPENAI_API_KEY or ""
        self.base_url = base_url or config.OPENAI_BASE_URL

    def explain(self, finding: Finding) -> str:
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY not set. Export it, add it to .env, or pass --no-ai."
            )

        from openai import OpenAI

        client_kwargs: dict[str, str] = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url

        client = OpenAI(**client_kwargs)

        user_prompt = build_finding_prompt(
            title=finding.title,
            severity=finding.severity.value,
            line=finding.line,
            rule_id=finding.rule_id,
            snippet=finding.snippet or "",
            description=finding.description,
        )

        try:
            return self._call_api(client, self.model, user_prompt)
        except Exception:
            if self.model != config.FALLBACK_MODEL:
                logger.warning(
                    "Model %s failed, falling back to %s",
                    self.model,
                    config.FALLBACK_MODEL,
                )
                try:
                    return self._call_api(client, config.FALLBACK_MODEL, user_prompt)
                except Exception:
                    logger.warning("Fallback model also failed, skipping AI explanation")
                    raise
            raise

    @staticmethod
    def _call_api(client: object, model: str, user_prompt: str) -> str:
        from openai import OpenAI

        assert isinstance(client, OpenAI)

        kwargs: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_completion_tokens": 4096,
        }

        # gpt-5 family models only support the default temperature (1).
        # Older models (gpt-4o, gpt-4o-mini, etc.) accept custom values.
        if not model.startswith("gpt-5"):
            kwargs["temperature"] = 0.3

        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""


class FallbackProvider(LLMProvider):
    """Template-based explanations when no LLM API key is available.

    Produces useful output without any external API call, so the tool
    is always functional even without an OpenAI key.
    """

    _TEMPLATES: dict[str, str] = {
        "reentrancy": (
            "**Reentrancy Vulnerability**\n\n"
            "The contract makes an external call before updating its own state. "
            "An attacker can deploy a malicious contract whose fallback function "
            "calls back into the vulnerable function, draining funds before the "
            "balance is zeroed out.\n\n"
            "**Recommendation:** Apply the checks-effects-interactions pattern — "
            "update all state variables *before* making external calls. "
            "Alternatively, use OpenZeppelin's `ReentrancyGuard` modifier."
        ),
        "unchecked-call": (
            "**Unchecked External Call**\n\n"
            "The return value of a low-level `.call()` is not checked. "
            "If the call fails (e.g. out-of-gas, revert), the contract "
            "continues executing as if nothing happened, potentially leaving "
            "it in an inconsistent state.\n\n"
            "**Recommendation:** Always capture the boolean return value and "
            "check it with `require(success, \"call failed\")`."
        ),
    }

    _DEFAULT = (
        "A potential security issue was detected. "
        "Review the code at the indicated location and consider the "
        "description above. Consult the Solidity security best practices "
        "at https://docs.soliditylang.org/en/latest/security-considerations.html"
    )

    def explain(self, finding: Finding) -> str:
        return self._TEMPLATES.get(finding.rule_id, self._DEFAULT)
