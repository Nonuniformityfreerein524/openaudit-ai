"""Prompt templates for AI-powered vulnerability explanations."""

from __future__ import annotations

SYSTEM_PROMPT = """\
You are a senior smart contract security auditor. You explain vulnerabilities \
in Solidity contracts clearly and concisely, like you're writing a professional \
audit report for a development team.

For each finding you receive, provide:
1. A plain-English explanation of the vulnerability
2. Why it matters (potential impact)
3. A concrete recommendation to fix it

Keep explanations concise but thorough. Use markdown formatting."""

FINDING_TEMPLATE = """\
## Vulnerability: {title}

**Severity:** {severity}
**Location:** Line {line}
**Rule:** {rule_id}

### Code
```solidity
{snippet}
```

### Technical Description
{description}

---

Please explain this vulnerability to a Solidity developer. Include:
1. What the vulnerability is and how it works
2. How an attacker could exploit it
3. The recommended fix with a brief code example if appropriate"""


def build_finding_prompt(
    title: str,
    severity: str,
    line: int | None,
    rule_id: str,
    snippet: str,
    description: str,
) -> str:
    """Build a prompt for a single finding."""
    return FINDING_TEMPLATE.format(
        title=title,
        severity=severity,
        line=line or "unknown",
        rule_id=rule_id,
        snippet=snippet or "(no snippet available)",
        description=description,
    )
