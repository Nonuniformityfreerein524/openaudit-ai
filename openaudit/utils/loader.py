"""File loading utilities for Solidity source files."""

from __future__ import annotations

from pathlib import Path

from openaudit.utils.types import ContractSource


def load_solidity_file(path: Path) -> ContractSource:
    """Read a Solidity file from disk and return a ContractSource."""
    resolved = path.resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"File not found: {resolved}")
    if not resolved.suffix == ".sol":
        raise ValueError(f"Expected a .sol file, got: {resolved.name}")
    content = resolved.read_text(encoding="utf-8")
    return ContractSource(path=resolved, content=content)


def discover_solidity_files(directory: Path) -> list[Path]:
    """Recursively find all .sol files under a directory."""
    resolved = directory.resolve()
    if not resolved.is_dir():
        raise NotADirectoryError(f"Not a directory: {resolved}")
    return sorted(resolved.rglob("*.sol"))
