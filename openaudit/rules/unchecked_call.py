"""Unchecked low-level call detector.

Detects uses of `.call()` whose boolean return value is not checked,
which can silently swallow failed transfers.
"""

from __future__ import annotations

import re

from openaudit.analyzer.parser import ASTNode, NodeKind, get_functions
from openaudit.rules.base import BaseRule
from openaudit.rules.registry import register
from openaudit.utils.types import ContractSource, Finding, Severity

_CHECKED_PATTERN = re.compile(r"\(\s*bool\s+\w+\s*,")


@register
class UncheckedCallRule(BaseRule):
    id = "unchecked-call"
    title = "Unchecked Low-Level Call"
    description = (
        "The return value of a low-level `.call()` is not checked. "
        "If the call fails, execution continues silently."
    )

    def run(self, ast: list[ASTNode], source: ContractSource) -> list[Finding]:
        findings: list[Finding] = []

        for func in get_functions(ast):
            for child in func.children:
                if child.kind != NodeKind.EXTERNAL_CALL:
                    continue
                if ".call" not in child.content:
                    continue
                if _return_value_is_checked(child, source):
                    continue

                findings.append(
                    Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        line=child.line,
                        description=(
                            f"In function `{func.name}()`: the return value of "
                            f"`.call()` on line {child.line} is not assigned to a variable "
                            f"or used in a require/assert. If the call fails the contract "
                            f"will continue executing."
                        ),
                        snippet=_get_line(source, child.line),
                        metadata={"function": func.name},
                    )
                )

        return findings


def _return_value_is_checked(node: ASTNode, source: ContractSource) -> bool:
    """Heuristic: check if the line captures the bool return."""
    line = source.lines[node.line - 1] if node.line <= len(source.lines) else ""
    if _CHECKED_PATTERN.search(line):
        return True
    if "require(" in line or "assert(" in line:
        return True
    prev = source.lines[node.line - 2] if node.line >= 2 else ""
    if _CHECKED_PATTERN.search(prev):
        return True
    return False


def _get_line(source: ContractSource, lineno: int, context: int = 1) -> str:
    lo = max(0, lineno - 1 - context)
    hi = min(len(source.lines), lineno + context)
    return "\n".join(f"{i + 1:>4} | {source.lines[i]}" for i in range(lo, hi))
