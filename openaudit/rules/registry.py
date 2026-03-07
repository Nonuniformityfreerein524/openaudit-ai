"""Rule registry — central catalog of all available detection rules.

Rules register themselves at import time via the `register` decorator.
The engine calls `get_enabled_rules()` to iterate over them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openaudit.rules.base import BaseRule

_RULES: dict[str, type[BaseRule]] = {}


def register(cls: type[BaseRule]) -> type[BaseRule]:
    """Class decorator that registers a rule in the global catalog."""
    _RULES[cls.id] = cls
    return cls


def get_enabled_rules() -> list[BaseRule]:
    """Instantiate and return all registered rules."""
    _discover_rules()
    return [rule_cls() for rule_cls in _RULES.values()]


def get_rule(rule_id: str) -> BaseRule | None:
    """Look up a single rule by ID."""
    _discover_rules()
    cls = _RULES.get(rule_id)
    return cls() if cls else None


def _discover_rules() -> None:
    """Import all built-in rule modules so they auto-register."""
    import openaudit.rules.reentrancy  # noqa: F401
    import openaudit.rules.unchecked_call  # noqa: F401
