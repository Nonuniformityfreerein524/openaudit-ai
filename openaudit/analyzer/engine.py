"""Core analysis engine — orchestrates parsing, rule execution, and result collection."""

from __future__ import annotations

from openaudit.analyzer.parser import parse_source
from openaudit.rules.registry import get_enabled_rules
from openaudit.utils.types import ContractSource, Finding


class AnalysisEngine:
    """Run all registered detection rules against a parsed contract."""

    def analyze(self, source: ContractSource) -> list[Finding]:
        """Parse the source, run every enabled rule, and return all findings."""
        ast = parse_source(source.content)
        findings: list[Finding] = []

        for rule in get_enabled_rules():
            rule_findings = rule.run(ast, source)
            findings.extend(rule_findings)

        findings.sort(key=lambda f: (f.line or 0))
        return findings
