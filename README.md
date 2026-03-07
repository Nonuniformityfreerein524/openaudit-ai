# 🛡️ OpenAudit AI

> AI-powered smart contract auditor that analyzes Solidity code and explains vulnerabilities like a security engineer.

OpenAudit AI combines **static analysis** with **LLM-powered explanations** to help developers find and understand security issues in their Solidity smart contracts.

---

## ✨ Features

- 🔍 **Static Analysis Engine** — Parses Solidity source and runs modular vulnerability detection rules
- 🔁 **Reentrancy Detection** — Identifies external calls made before state updates
- ⚠️ **Unchecked Call Detection** — Flags low-level `.call()` results that aren't validated
- 🤖 **AI Explanations** — Uses GPT-5 to explain vulnerabilities in plain English (optional; works without an API key)
- 💻 **CLI Tool** — `oaudit` command for single-file analysis and directory scanning
- 🩺 **Diagnostics** — `oaudit doctor` to check your AI configuration at a glance
- 📄 **JSON Output** — Machine-readable output for CI/CD integration
- 🧩 **Extensible Rule System** — Add new detectors by subclassing `BaseRule`
- 🔐 **Fail-Safe** — Never crashes due to AI issues; gracefully falls back to templates

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/openaudit-ai/openaudit-ai.git
cd openaudit-ai

# Install in development mode
pip install -e ".[dev]"
```

---

## 🚀 Quick Start

Analyze a single contract:

```bash
oaudit analyze examples/vulnerable_bank.sol
```

Scan an entire directory:

```bash
oaudit scan ./contracts/
```

Get JSON output:

```bash
oaudit analyze contract.sol --json
```

Skip AI explanations (no API key needed):

```bash
oaudit analyze contract.sol --no-ai
```

Check your configuration:

```bash
oaudit doctor
```

---

## ⚙️ AI Configuration

OpenAudit AI reads configuration from a `.env` file in the project root (or from environment variables).

### 🔧 Setup

```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
```

The `.env` file supports these variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | For AI explanations | — | Your OpenAI API key |
| `OPENAI_BASE_URL` | No | `https://api.openai.com/v1` | API endpoint (change for Azure, local proxies, etc.) |
| `OPENAI_MODEL` | No | `gpt-5-mini` | Model used for explanations |

### 🔄 Changing Models

Set the model in `.env`:

```
OPENAI_MODEL=gpt-5-mini
```

Available models: `gpt-5.2`, `gpt-5.2-pro`, `gpt-5.1`, `gpt-5`, `gpt-5-mini`, `gpt-5-nano`

Or override per-command with `--model`:

```bash
oaudit analyze contract.sol --model gpt-5.2
```

The CLI flag takes priority over the `.env` value.

If the configured model is unavailable (API error, model not found), the tool automatically falls back to `gpt-4o-mini`.

### 🚫 Disabling AI

Skip AI explanations entirely (no API key needed):

```bash
oaudit analyze contract.sol --no-ai
```

When no `OPENAI_API_KEY` is set, the tool automatically uses built-in template explanations — it never crashes due to missing AI configuration.

### 🩺 Checking Your Configuration

```bash
oaudit doctor
```

Example output:

```
OpenAudit AI — Configuration Diagnostic

  AI Provider:    OpenAI
  Model:          gpt-5-mini
  API Key:        detected
  Base URL:       https://api.openai.com/v1
  Fallback Mode:  disabled
```

---

## 📖 CLI Reference

```
oaudit analyze <file.sol>     🔍 Analyze a single Solidity file
oaudit scan <directory>       📂 Scan all .sol files in a directory
oaudit doctor                 🩺 Diagnose AI provider configuration
oaudit version                📌 Show version
```

### Options

| Flag | Description |
|------|-------------|
| `--json` / `-j` | 📄 Output results as JSON |
| `--no-ai` | 🚫 Skip AI-powered explanations |
| `--model` / `-m` | 🤖 Specify the LLM model to use |

---

## 🖥️ Example Output

```
⚠️ Reentrancy Vulnerability
  Severity: HIGH
  Location: line 25

  In function `withdraw()`: external call on line 25 occurs before
  state update on line 28. The call target `msg.sender` could
  re-enter this function before `balances` is updated.

  ╭─────────────────── AI Explanation ───────────────────╮
  │                                                      │
  │ The contract sends ETH before updating the user's    │
  │ balance. An attacker contract could repeatedly call  │
  │ withdraw() via its fallback function, draining the   │
  │ contract.                                            │
  │                                                      │
  │ Fix: Apply the checks-effects-interactions pattern   │
  │ or use OpenZeppelin's ReentrancyGuard.               │
  ╰──────────────────────────────────────────────────────╯
```

---

## 🏗️ Project Structure

```
openaudit-ai/
├── openaudit/
│   ├── config.py     ⚙️  Centralized configuration (.env + defaults)
│   ├── cli/          💻  CLI commands (Typer)
│   ├── analyzer/     🔍  Static analysis engine & parser
│   ├── rules/        📏  Vulnerability detection rules
│   ├── ai/           🤖  LLM integration & prompt templates
│   ├── reports/      📊  Output formatting (terminal, JSON)
│   ├── utils/        🔧  Shared types & helpers
│   └── api/          🌐  Future REST API (FastAPI)
├── tests/            🧪  pytest test suite (32 tests)
├── examples/         📝  Sample vulnerable contracts
├── docs/             📚  Architecture deep-dive
├── .env.example      🔑  Environment variable template
└── pyproject.toml    📦  Package configuration
```

---

## 🧩 Adding a New Rule

1. Create a file in `openaudit/rules/`:

```python
from openaudit.rules.base import BaseRule
from openaudit.rules.registry import register

@register
class MyRule(BaseRule):
    id = "my-rule"
    title = "My Custom Rule"
    description = "Detects ..."

    def run(self, ast, source):
        findings = []
        # Your detection logic here
        return findings
```

2. Import it in `openaudit/rules/registry.py` inside `_discover_rules()`.

3. Add a template in `openaudit/ai/provider.py` `FallbackProvider._TEMPLATES`.

---

## 🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=openaudit

# Lint
ruff check openaudit/ tests/
```

---

## 🗺️ Roadmap

- [ ] 📏 Additional rules (integer overflow, tx.origin, selfdestruct, etc.)
- [ ] 🌐 REST API via FastAPI
- [ ] 🤖 GitHub PR bot for automated reviews
- [ ] 🏠 Hosted service with dashboard
- [ ] 🌳 tree-sitter based Solidity parser
- [ ] 📁 Multi-file / import resolution support
- [ ] 🔗 Slither integration bridge

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

[MIT](LICENSE)
