"""Core domain types shared across all modules."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Vulnerability severity levels aligned with common audit standards."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single vulnerability finding produced by a detection rule."""

    rule_id: str = Field(description="Machine-readable rule identifier, e.g. 'reentrancy'")
    title: str = Field(description="Short human-readable title")
    severity: Severity
    line: int | None = Field(default=None, description="1-based line number in the source file")
    column: int | None = Field(default=None)
    description: str = Field(description="Technical description of the issue")
    snippet: str | None = Field(default=None, description="Relevant source code fragment")
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditResult(BaseModel):
    """Complete audit output for a single file."""

    file: str
    findings: list[Finding] = Field(default_factory=list)
    ai_explanations: dict[int, str] = Field(
        default_factory=dict,
        description="Mapping of finding index -> AI explanation text",
    )
    error: str | None = None


class ContractSource(BaseModel):
    """Loaded Solidity source ready for analysis."""

    path: Path
    content: str
    lines: list[str] = Field(default_factory=list)

    def model_post_init(self, _context: Any) -> None:
        if not self.lines:
            self.lines = self.content.splitlines()
