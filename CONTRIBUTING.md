# Contributing to OpenAudit AI

Thanks for your interest in contributing! This document covers how to get started.

## Development Setup

```bash
git clone https://github.com/openaudit-ai/openaudit-ai.git
cd openaudit-ai
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

## Code Style

- Python 3.10+ with type hints on all public functions
- Format with `ruff` — the project config lives in `pyproject.toml`
- Docstrings on modules and public classes/functions
- Keep modules focused and small

```bash
ruff check openaudit/ tests/
ruff format openaudit/ tests/
```

## Adding a Vulnerability Rule

The rule system is designed to be easy to extend:

1. **Create a new file** in `openaudit/rules/` (e.g. `integer_overflow.py`)
2. **Subclass `BaseRule`** and implement the `run()` method
3. **Decorate with `@register`** so the engine discovers it automatically
4. **Register the import** in `openaudit/rules/registry.py` inside `_discover_rules()`
5. **Add a fallback template** in `openaudit/ai/provider.py` for non-AI explanations
6. **Write tests** in `tests/test_rules.py`

Each rule receives the parsed AST and the original source, and returns a list of `Finding` objects.

## Pull Request Guidelines

1. Fork the repo and create a feature branch from `main`
2. Add or update tests for any new functionality
3. Ensure `pytest` passes and `ruff check` is clean
4. Write a clear PR description explaining what changed and why
5. Keep PRs focused — one feature or fix per PR

## Reporting Issues

Open an issue on GitHub with:

- A description of the problem or suggestion
- Steps to reproduce (for bugs)
- The Solidity code that triggered the issue (if applicable)
- Expected vs actual behavior

## Architecture Decisions

- **Parser:** The current parser is regex-based for simplicity. A tree-sitter or ANTLR grammar is planned for better accuracy.
- **AI Module:** Designed with a provider interface so OpenAI can be swapped for Anthropic, local models, etc.
- **Rule System:** Auto-registration via decorators. Rules are stateless and receive everything they need via arguments.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
