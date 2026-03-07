"""Reentrancy vulnerability detector.

Detects functions where an external call (call/send/transfer) occurs
before a state variable is updated — the classic reentrancy pattern
exploited in the DAO hack.

Pattern:
    1. External call on line N  (e.g. msg.sender.call{value: ...}(""))
    2. State write on line M    (e.g. balances[msg.sender] = 0)
    3. M > N  →  state update happens *after* the external call
"""

from __future__ import annotations

from openaudit.analyzer.parser import ASTNode, NodeKind, get_functions
from openaudit.rules.base import BaseRule
from openaudit.rules.registry import register
from openaudit.utils.types import ContractSource, Finding, Severity


@register
class ReentrancyRule(BaseRule):
    id = "reentrancy"
    title = "Reentrancy Vulnerability"
    description = (
        "An external call is made before the contract's state is updated. "
        "An attacker can re-enter the function before the state change takes effect."
    )

    def run(self, ast: list[ASTNode], source: ContractSource) -> list[Finding]:
        findings: list[Finding] = []

        for func in get_functions(ast):
            external_calls: list[ASTNode] = []
            state_writes: list[ASTNode] = []

            for child in func.children:
                if child.kind == NodeKind.EXTERNAL_CALL:
                    external_calls.append(child)
                elif child.kind == NodeKind.STATE_WRITE:
                    state_writes.append(child)

            for call in external_calls:
                for write in state_writes:
                    if write.line > call.line:
                        snippet = _build_snippet(source, call.line, write.line)
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                title=self.title,
                                severity=Severity.HIGH,
                                line=call.line,
                                description=(
                                    f"In function `{func.name}()`: external call on line "
                                    f"{call.line} occurs before state update on line "
                                    f"{write.line}. The call target `{call.name}` could "
                                    f"re-enter this function before `{write.name}` is updated."
                                ),
                                snippet=snippet,
                                metadata={
                                    "function": func.name,
                                    "call_line": str(call.line),
                                    "write_line": str(write.line),
                                    "call_target": call.name,
                                    "state_var": write.name,
                                },
                            )
                        )

        return findings


def _build_snippet(source: ContractSource, start: int, end: int, context: int = 2) -> str:
    """Extract a source snippet with a few lines of context."""
    lo = max(0, start - 1 - context)
    hi = min(len(source.lines), end + context)
    numbered = [f"{i + 1:>4} | {source.lines[i]}" for i in range(lo, hi)]
    return "\n".join(numbered)
