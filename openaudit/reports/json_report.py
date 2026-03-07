"""JSON output formatter for programmatic consumption."""

from __future__ import annotations

import json

from openaudit.utils.types import AuditResult


def results_to_json(results: list[AuditResult], pretty: bool = True) -> str:
    """Serialize audit results to a JSON string."""
    payload = [_serialize_result(r) for r in results]
    return json.dumps(payload, indent=2 if pretty else None)


def _serialize_result(result: AuditResult) -> dict:
    return {
        "file": result.file,
        "error": result.error,
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity.value,
                "line": f.line,
                "description": f.description,
                "snippet": f.snippet,
                "ai_explanation": result.ai_explanations.get(idx),
            }
            for idx, f in enumerate(result.findings)
        ],
    }
