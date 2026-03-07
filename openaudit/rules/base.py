"""Base class for all vulnerability detection rules.

Every rule must subclass BaseRule and implement the `run` method.
This provides a uniform interface for the analysis engine and makes
it trivial to add new detectors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from openaudit.analyzer.parser import ASTNode
from openaudit.utils.types import ContractSource, Finding


class BaseRule(ABC):
    """Abstract base for vulnerability detection rules."""

    id: str
    title: str
    description: str

    @abstractmethod
    def run(self, ast: list[ASTNode], source: ContractSource) -> list[Finding]:
        """Analyze the AST and return any findings.

        Args:
            ast: Parsed AST nodes for the contract.
            source: The original source with full text + line list.

        Returns:
            A list of Finding objects (may be empty).
        """
