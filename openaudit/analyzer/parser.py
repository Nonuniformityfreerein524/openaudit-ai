"""Lightweight Solidity parser that extracts structural information for analysis.

This is intentionally not a full grammar parser — it extracts the AST-like
structures that vulnerability rules need (contracts, functions, statements,
external calls, state mutations) using pattern matching on source lines.

A full Solidity grammar parser (tree-sitter, ANTLR) can replace this later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class NodeKind(str, Enum):
    CONTRACT = "contract"
    FUNCTION = "function"
    MODIFIER = "modifier"
    EVENT = "event"
    STATEMENT = "statement"
    EXTERNAL_CALL = "external_call"
    STATE_WRITE = "state_write"


@dataclass
class ASTNode:
    """Lightweight AST node representing a parsed Solidity element."""

    kind: NodeKind
    name: str
    line: int
    end_line: int | None = None
    content: str = ""
    children: list[ASTNode] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


# --- Pattern constants ---

_CONTRACT_RE = re.compile(
    r"^\s*(abstract\s+)?contract\s+(\w+)", re.MULTILINE
)
_FUNCTION_RE = re.compile(
    r"^\s*function\s+(\w+)\s*\(", re.MULTILINE
)
_MODIFIER_RE = re.compile(
    r"^\s*modifier\s+(\w+)\s*[\({]", re.MULTILINE
)

_EXTERNAL_CALL_PATTERNS = [
    re.compile(r"\.call\s*[\({]"),
    re.compile(r"\.delegatecall\s*[\({]"),
    re.compile(r"\.staticcall\s*[\({]"),
    re.compile(r"\.send\s*\("),
    re.compile(r"\.transfer\s*\("),
]

_STATE_WRITE_RE = re.compile(
    r"^\s*(\w+(?:\[.*?\])?(?:\.\w+)*)\s*(?:=|\+=|-=|\*=|/=)\s*"
)

_MAPPING_ACCESS_RE = re.compile(
    r"(\w+)\s*\[.*?\]\s*(?:=|\+=|-=)"
)

_DECLARATION_RE = re.compile(
    r"^\s*(?:uint\d*|int\d*|address|bool|string|bytes\d*|mapping)\b"
)


def parse_source(source: str) -> list[ASTNode]:
    """Parse Solidity source into a flat list of AST nodes.

    Returns high-level nodes (contracts, functions) with children
    representing statements, external calls, and state writes.
    """
    lines = source.splitlines()
    nodes: list[ASTNode] = []
    current_contract: ASTNode | None = None
    current_function: ASTNode | None = None
    brace_depth = 0
    func_brace_start = 0

    for lineno_0, raw_line in enumerate(lines):
        lineno = lineno_0 + 1
        line = raw_line.strip()

        brace_depth += raw_line.count("{") - raw_line.count("}")

        contract_match = _CONTRACT_RE.match(raw_line)
        if contract_match:
            current_contract = ASTNode(
                kind=NodeKind.CONTRACT,
                name=contract_match.group(2),
                line=lineno,
                content=line,
            )
            nodes.append(current_contract)
            current_function = None
            continue

        func_match = _FUNCTION_RE.match(raw_line)
        if func_match:
            current_function = ASTNode(
                kind=NodeKind.FUNCTION,
                name=func_match.group(1),
                line=lineno,
                content=line,
            )
            func_brace_start = brace_depth
            if current_contract:
                current_contract.children.append(current_function)
            else:
                nodes.append(current_function)
            continue

        if current_function and brace_depth < func_brace_start:
            current_function.end_line = lineno
            current_function = None

        if not current_function or not line or line.startswith("//"):
            continue

        for pattern in _EXTERNAL_CALL_PATTERNS:
            if pattern.search(line):
                call_node = ASTNode(
                    kind=NodeKind.EXTERNAL_CALL,
                    name=_extract_call_target(line),
                    line=lineno,
                    content=line,
                )
                current_function.children.append(call_node)
                break

        if _STATE_WRITE_RE.match(line) and not _DECLARATION_RE.match(raw_line):
            mapping_match = _MAPPING_ACCESS_RE.search(line)
            write_node = ASTNode(
                kind=NodeKind.STATE_WRITE,
                name=mapping_match.group(1) if mapping_match else line.split("=")[0].strip(),
                line=lineno,
                content=line,
            )
            current_function.children.append(write_node)

    if current_function and current_function.end_line is None:
        current_function.end_line = len(lines)

    return nodes


def _extract_call_target(line: str) -> str:
    """Pull the target expression from an external call line."""
    for keyword in (".call", ".delegatecall", ".staticcall", ".send", ".transfer"):
        idx = line.find(keyword)
        if idx != -1:
            prefix = line[:idx].strip()
            parts = prefix.rsplit(" ", 1)
            return parts[-1] if parts else prefix
    return "unknown"


def get_functions(nodes: list[ASTNode]) -> list[ASTNode]:
    """Extract all function nodes from the parsed AST."""
    funcs: list[ASTNode] = []
    for node in nodes:
        if node.kind == NodeKind.FUNCTION:
            funcs.append(node)
        for child in node.children:
            if child.kind == NodeKind.FUNCTION:
                funcs.append(child)
    return funcs
