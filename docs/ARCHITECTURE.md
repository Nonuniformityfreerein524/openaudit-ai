# 🏗️ OpenAudit AI — Architecture Deep Dive

How the tool actually works, what gets sent to OpenAI, and what you can (and can't) trust.

---

## 📑 Table of Contents

1. [🖼️ The Big Picture](#-the-big-picture)
2. [🔄 Step-by-Step: What Happens When You Run `oaudit analyze`](#-step-by-step-what-happens-when-you-run-oaudit-analyze)
3. [📝 Stage 1: Parsing (Local, No AI)](#-stage-1-parsing-local-no-ai)
4. [📏 Stage 2: Rule Engine (Local, No AI)](#-stage-2-rule-engine-local-no-ai)
5. [🤖 Stage 3: AI Explanations (Optional, Calls OpenAI)](#-stage-3-ai-explanations-optional-calls-openai)
6. [📤 What Exactly Gets Sent to OpenAI?](#-what-exactly-gets-sent-to-openai)
7. [🧠 What Does OpenAI Actually Do?](#-what-does-openai-actually-do)
8. [🔌 What Happens Without an OpenAI Key?](#-what-happens-without-an-openai-key)
9. [⚙️ Configuration & .env](#️-configuration--env)
10. [🛡️ Fail-Safe & Model Fallback](#️-fail-safe--model-fallback)
11. [🤔 Can You Trust It?](#-can-you-trust-it)
12. [📊 Data Flow Diagram](#-data-flow-diagram)
13. [📂 Full Code Walkthrough](#-full-code-walkthrough)

---

## 🖼️ The Big Picture

OpenAudit AI has **two completely separate systems** working together:

| System | What it does | Where it runs | Needs internet? |
|--------|-------------|---------------|-----------------|
| 🔍 **Static Analysis Engine** | Parses Solidity, detects vulnerability patterns | 100% local on your machine | No |
| 🤖 **AI Explanation Module** | Takes findings and generates human-readable explanations | Calls OpenAI API (or uses local templates) | Only if you want GPT explanations |

**The critical point:** The AI does NOT do the auditing. The static analysis engine does. The AI just explains what was already found.

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  📄 Your .sol   │────>│ 🔍 Static        │────>│  📋 Findings     │
│   file          │     │  Analysis         │     │  (structured)    │
│                 │     │  (local, no AI)   │     │                  │
└─────────────────┘     └──────────────────┘     └────────┬─────────┘
                                                          │
                                               ┌──────────▼─────────┐
                                               │ 🤖 AI Explainer    │
                                               │  (optional)        │
                                               └──────────┬─────────┘
                                                          │
                                               ┌──────────▼─────────┐
                                               │ 🖥️ Terminal / JSON │
                                               │  output            │
                                               └────────────────────┘
```

---

## 🔄 Step-by-Step: What Happens When You Run `oaudit analyze`

When you run:

```bash
oaudit analyze examples/vulnerable_bank.sol
```

Here is the exact execution path through the code:

### 1️⃣ Configuration loads from `.env`

`openaudit/config.py` is imported — this triggers `load_dotenv()` which reads your `.env` file and populates `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and `OPENAI_MODEL`.

```python
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None
OPENAI_BASE_URL: str | None = os.getenv("OPENAI_BASE_URL") or None
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-5-mini")
FALLBACK_MODEL = "gpt-4o-mini"
```

### 2️⃣ CLI parses the command

`openaudit/cli/main.py` — the Typer framework routes to the `analyze()` function:

```python
@app.command()
def analyze(
    file: Path = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
    no_ai: bool = typer.Option(False, "--no-ai"),
    model: Optional[str] = typer.Option(None, "--model"),
) -> None:
    result = _audit_file(file, use_ai=not no_ai, model=model)
```

### 3️⃣ `_audit_file()` orchestrates the pipeline

```python
def _audit_file(file, use_ai=True, model=None) -> AuditResult:
    source = load_solidity_file(file)      # Read the .sol file from disk
    findings = engine.analyze(source)       # Static analysis (100% LOCAL)

    if model:                               # CLI --model flag overrides .env
        explainer = Explainer(provider=OpenAIProvider(model=model))
    else:
        explainer = Explainer(use_ai=use_ai)  # Auto-select provider from config

    ai_explanations = explainer.explain_all(findings)
    return AuditResult(file=str(file), findings=findings, ai_explanations=ai_explanations)
```

That's the entire pipeline. Now let's go deep into each stage.

---

## 📝 Stage 1: Parsing (Local, No AI)

**File:** `openaudit/analyzer/parser.py`

The parser reads your `.sol` file as plain text and uses **regex pattern matching** to extract a lightweight AST (Abstract Syntax Tree). No AI involved — this is pure string processing.

### What it extracts

The parser scans every line looking for these patterns:

| Pattern | Regex | What it finds |
|---------|-------|---------------|
| 📦 Contract declarations | `^\s*(abstract\s+)?contract\s+(\w+)` | `contract VulnerableBank {` |
| 🔧 Function declarations | `^\s*function\s+(\w+)\s*\(` | `function withdraw() external {` |
| 📞 External calls | `\.call\s*[\({]`, `\.send\s*\(`, `\.transfer\s*\(` | `msg.sender.call{value: amount}("")` |
| ✏️ State writes | `^\s*(\w+(?:\[.*?\])?)\s*(?:=\|\+=\|-=)` | `balances[msg.sender] = 0` |
| 🚫 Variable declarations (excluded) | `^\s*(?:uint\d*\|address\|bool\|...)` | Filters out `uint256 amount = ...` |

### What it produces

For a function like:

```solidity
function withdraw() external {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] = 0;
}
```

The parser produces this tree:

```
ASTNode(kind=FUNCTION, name="withdraw", line=22)
├── ASTNode(kind=EXTERNAL_CALL, name="msg.sender", line=25)
└── ASTNode(kind=STATE_WRITE, name="balances", line=28)
```

Note: `uint256 amount = balances[msg.sender]` is filtered out — the `_DECLARATION_RE` regex recognizes it as a local variable declaration, not a state write.

### ⚠️ Important limitation

This parser is **regex-based, not a real Solidity grammar parser**. It works well for common patterns but can miss:
- Multi-line statements
- Complex nested expressions
- Inline assembly
- Deeply nested conditionals around calls

The roadmap includes replacing this with a **tree-sitter** grammar for higher accuracy.

---

## 📏 Stage 2: Rule Engine (Local, No AI)

**Files:** `openaudit/analyzer/engine.py`, `openaudit/rules/reentrancy.py`, `openaudit/rules/unchecked_call.py`

The engine takes the AST from Stage 1 and runs every registered detection rule against it. Still **100% local, no network calls**.

### How the engine works

```python
class AnalysisEngine:
    def analyze(self, source: ContractSource) -> list[Finding]:
        ast = parse_source(source.content)       # Get the AST from Stage 1
        findings: list[Finding] = []

        for rule in get_enabled_rules():          # Loop through all rules
            rule_findings = rule.run(ast, source)  # Each rule inspects the AST
            findings.extend(rule_findings)

        findings.sort(key=lambda f: (f.line or 0))
        return findings
```

### How the reentrancy rule works

The reentrancy detector implements a simple but effective pattern:

```
For each function in the AST:
    1. Collect all EXTERNAL_CALL children (lines with .call/.send/.transfer)
    2. Collect all STATE_WRITE children (lines that assign to storage)
    3. If any STATE_WRITE line number > EXTERNAL_CALL line number:
       → Flag it. The state is being updated AFTER the external call.
```

In code:

```python
for func in get_functions(ast):
    external_calls = [c for c in func.children if c.kind == EXTERNAL_CALL]
    state_writes = [c for c in func.children if c.kind == STATE_WRITE]

    for call in external_calls:
        for write in state_writes:
            if write.line > call.line:    # ← The core check
                findings.append(Finding(
                    rule_id="reentrancy",
                    severity=Severity.HIGH,
                    line=call.line,
                    ...
                ))
```

For `vulnerable_bank.sol`:
- Line 25: `msg.sender.call{value: amount}("")` — 📞 EXTERNAL_CALL
- Line 28: `balances[msg.sender] = 0` — ✏️ STATE_WRITE
- 28 > 25 → 🚨 **flagged**

For `safe_bank.sol`:
- Line 24: `balances[msg.sender] = 0` — ✏️ STATE_WRITE
- Line 27: `msg.sender.call{value: amount}("")` — 📞 EXTERNAL_CALL
- State write comes BEFORE the call → ✅ **not flagged**

### What a Finding looks like

The rule produces a structured object — not a vague opinion, but concrete data:

```json
{
    "rule_id": "reentrancy",
    "title": "Reentrancy Vulnerability",
    "severity": "high",
    "line": 25,
    "description": "In function `withdraw()`: external call on line 25 occurs before state update on line 28.",
    "snippet": "  23 |     require(amount > 0, ...);\n  25 |     msg.sender.call{value: amount}(\"\");\n  28 |     balances[msg.sender] = 0;",
    "metadata": {
        "function": "withdraw",
        "call_line": "25",
        "write_line": "28",
        "call_target": "msg.sender",
        "state_var": "balances"
    }
}
```

**This is the audit.** Everything above is deterministic, reproducible, and runs with zero network access. The same input always produces the same findings.

---

## 🤖 Stage 3: AI Explanations (Optional, Calls OpenAI)

**Files:** `openaudit/ai/explainer.py`, `openaudit/ai/provider.py`, `openaudit/ai/prompts.py`

After the static analysis is complete and findings are produced, the AI module **optionally** explains each finding in plain English.

### Provider selection logic

```python
class Explainer:
    def __init__(self, provider=None, use_ai=True):
        if provider:
            self.provider = provider                # Explicit provider passed in
        elif use_ai and config.has_api_key():
            self.provider = OpenAIProvider()         # Has API key → use GPT
        else:
            self.provider = FallbackProvider()       # No key → use templates

        self._fallback = FallbackProvider()          # Always kept for fail-safe
```

Three paths:

| Condition | Provider | Network call? |
|-----------|----------|---------------|
| `--no-ai` flag | 📝 `FallbackProvider` | No |
| No `OPENAI_API_KEY` set | 📝 `FallbackProvider` | No |
| API key is set | 🤖 `OpenAIProvider` | Yes, calls OpenAI |

---

## 📤 What Exactly Gets Sent to OpenAI?

When the `OpenAIProvider` is active, here is the **exact API call** made for each finding:

```python
client = OpenAI(
    api_key=config.OPENAI_API_KEY,
    base_url=config.OPENAI_BASE_URL,     # from .env (or OpenAI default)
)

kwargs = {
    "model": config.OPENAI_MODEL,         # e.g. "gpt-5-mini" from .env
    "messages": [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ],
    "max_completion_tokens": 4096,
}

# GPT-5 family only supports default temperature (1)
# Older models (gpt-4o, etc.) accept custom values
if not model.startswith("gpt-5"):
    kwargs["temperature"] = 0.3

response = client.chat.completions.create(**kwargs)
```

### The system prompt (sent once per call)

```
You are a senior smart contract security auditor. You explain vulnerabilities
in Solidity contracts clearly and concisely, like you're writing a professional
audit report for a development team.

For each finding you receive, provide:
1. A plain-English explanation of the vulnerability
2. Why it matters (potential impact)
3. A concrete recommendation to fix it

Keep explanations concise but thorough. Use markdown formatting.
```

### The user prompt (per finding)

For the reentrancy finding, this is what gets sent:

```
## Vulnerability: Reentrancy Vulnerability

**Severity:** high
**Location:** Line 25
**Rule:** reentrancy

### Code
​```solidity
  23 |         require(amount > 0, "No balance");
  24 |
  25 |         (bool success, ) = msg.sender.call{value: amount}("");
  26 |         require(success, "Transfer failed");
  27 |
  28 |         balances[msg.sender] = 0;
  29 |         emit Withdrawal(msg.sender, amount);
  30 |     }
​```

### Technical Description
In function `withdraw()`: external call on line 25 occurs before state update
on line 28. The call target `msg.sender` could re-enter this function before
`balances` is updated.

---

Please explain this vulnerability to a Solidity developer. Include:
1. What the vulnerability is and how it works
2. How an attacker could exploit it
3. The recommended fix with a brief code example if appropriate
```

### What gets sent — summary

| Data sent to OpenAI | Included? |
|---------------------|-----------|
| ✅ The vulnerability type | Yes — `"reentrancy"` |
| ✅ The severity level | Yes — `"high"` |
| ✅ The code snippet (6-10 lines) | Yes — just the relevant lines |
| ✅ The technical description | Yes |
| ❌ The entire .sol file | **No** |
| ❌ Your file path | **No** |
| ❌ Your project name or repo URL | **No** |
| ❌ Any other files | **No** |

**Key point:** We do NOT send the full contract to OpenAI asking "is this bad?". We send only a small code snippet plus the structured finding that our local engine already identified. The AI's job is to write a good explanation, not to discover the vulnerability.

---

## 🧠 What Does OpenAI Actually Do?

OpenAI receives:
1. 🎭 A role instruction ("you are a security auditor")
2. 📋 A vulnerability finding we already detected (type, severity, snippet, description)
3. 📝 A request to explain it in plain English

It returns something like:

> **Reentrancy Vulnerability**
>
> This function sends ETH to `msg.sender` via a low-level `.call()` on line 25, but doesn't
> update the sender's balance until line 28. An attacker can deploy a contract whose `receive()`
> or `fallback()` function calls `withdraw()` again before the balance is set to zero.
>
> Each re-entrant call will pass the `require(amount > 0)` check because the balance hasn't
> been updated yet, allowing the attacker to drain the entire contract.
>
> **Fix:** Apply the checks-effects-interactions pattern:
> ```solidity
> balances[msg.sender] = 0;  // Update state first
> (bool success, ) = msg.sender.call{value: amount}("");  // Then send
> ```

**The AI is a writer, not an auditor.** It takes our structured finding and turns it into a paragraph a developer can understand. It adds context about exploit scenarios and code fix examples that our template system can't generate dynamically.

---

## 🔌 What Happens Without an OpenAI Key?

The tool works perfectly fine. The `FallbackProvider` kicks in and uses hardcoded explanation templates:

```python
class FallbackProvider(LLMProvider):
    _TEMPLATES = {
        "reentrancy": (
            "**Reentrancy Vulnerability**\n\n"
            "The contract makes an external call before updating its own state. "
            "An attacker can deploy a malicious contract whose fallback function "
            "calls back into the vulnerable function, draining funds before the "
            "balance is zeroed out.\n\n"
            "**Recommendation:** Apply the checks-effects-interactions pattern — "
            "update all state variables *before* making external calls. "
            "Alternatively, use OpenZeppelin's `ReentrancyGuard` modifier."
        ),
        "unchecked-call": ( ... ),
    }

    def explain(self, finding: Finding) -> str:
        return self._TEMPLATES.get(finding.rule_id, self._DEFAULT)
```

The **`--no-ai` flag** explicitly selects this path even if you have an API key set.

---

## ⚙️ Configuration & .env

**File:** `openaudit/config.py`

All configuration is centralized in one module. The `.env` file is loaded once at import time via `python-dotenv`.

```python
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

OPENAI_API_KEY: str | None = os.getenv("OPENAI_API_KEY") or None
OPENAI_BASE_URL: str | None = os.getenv("OPENAI_BASE_URL") or None
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-5-mini")
FALLBACK_MODEL = "gpt-4o-mini"
```

### Priority order for model selection

```
CLI --model flag  >  .env OPENAI_MODEL  >  default ("gpt-5-mini")
```

### The `oaudit doctor` command

```bash
$ oaudit doctor

OpenAudit AI — Configuration Diagnostic

  AI Provider:    OpenAI
  Model:          gpt-5-mini
  API Key:        detected
  Base URL:       https://api.openai.com/v1
  Fallback Mode:  disabled
```

---

## 🛡️ Fail-Safe & Model Fallback

The tool is designed to **never crash because of AI issues**. There are two layers of protection:

### Layer 1: Model fallback (inside `OpenAIProvider`)

If the configured model (e.g. `gpt-5-mini`) fails for any reason, the provider retries with `gpt-4o-mini`:

```python
try:
    return self._call_api(client, self.model, user_prompt)
except Exception:
    if self.model != config.FALLBACK_MODEL:
        # Retry with gpt-4o-mini
        return self._call_api(client, config.FALLBACK_MODEL, user_prompt)
    raise
```

### Layer 2: Provider fallback (inside `Explainer`)

If the entire OpenAI call fails (bad key, network error, both models down), the `Explainer` catches the exception and falls back to `FallbackProvider` templates:

```python
def explain(self, finding: Finding) -> str:
    try:
        return self.provider.explain(finding)
    except Exception as exc:
        logger.warning("AI explanation failed (%s), using fallback", exc)
        return self._fallback.explain(finding)
```

### 🔄 Fallback chain visualization

```
gpt-5-mini (configured model)
    │
    ├── ✅ Success → return AI explanation
    │
    └── ❌ Fails → try gpt-4o-mini (fallback model)
                        │
                        ├── ✅ Success → return AI explanation
                        │
                        └── ❌ Fails → use FallbackProvider templates
                                        │
                                        └── ✅ Always works (no network)
```

### ⚡ GPT-5 compatibility notes

GPT-5 family models have different API requirements than older models:

| Parameter | GPT-5 family | GPT-4o family |
|-----------|-------------|---------------|
| `max_tokens` | ❌ Not supported | ✅ Supported |
| `max_completion_tokens` | ✅ Required | ✅ Supported |
| `temperature` (custom) | ❌ Only default (1) | ✅ Supported |
| Reasoning tokens | ✅ Uses ~256+ internal reasoning tokens | ❌ N/A |

The provider handles this automatically:

```python
kwargs = {"max_completion_tokens": 4096}

if not model.startswith("gpt-5"):
    kwargs["temperature"] = 0.3   # Only for non-GPT-5 models
```

`max_completion_tokens` is set to 4096 because GPT-5 models use internal reasoning tokens (~256+) that eat into the budget before producing visible output.

---

## 🤔 Can You Trust It?

Honest answer: **partially, and here's why.**

### ✅ What you CAN trust

The static analysis findings (reentrancy, unchecked-call) are **deterministic pattern matching**. If the tool says "external call on line 25 before state write on line 28," that is an objective, verifiable fact about the code. You can look at line 25 and line 28 and confirm it yourself.

The rule engine:
- Does not hallucinate line numbers
- Does not invent code that isn't there
- Produces the same output every time for the same input
- Runs entirely on your machine with no network access

### ⚠️ What you should verify

1. **False positives are possible.** The pattern "external call before state write" is a necessary condition for reentrancy, but not sufficient. There may be legitimate reasons the code is ordered that way (e.g., the call target is a trusted contract, or there's a reentrancy guard modifier the parser didn't detect). The tool flags the **pattern**, not a guaranteed exploit.

2. **False negatives are certain.** The regex-based parser will miss vulnerabilities that involve:
   - Multi-line call expressions
   - Calls inside nested if/else branches
   - Indirect calls through interfaces or libraries
   - Cross-function reentrancy
   - Vulnerability types we haven't written rules for yet (integer overflow, access control, etc.)

3. **The AI explanations are only as good as the LLM.** When using GPT, the explanation is non-deterministic. It usually gives correct advice for well-known vulnerability types, but:
   - It could give slightly wrong fix suggestions for edge cases
   - It might sound confident about something it's wrong about
   - Different runs may produce different wording

### 🚫 What this tool is NOT

- **Not a replacement for a professional audit.** Professional auditors use formal verification, manual review, symbolic execution, fuzzing, and deep protocol-level analysis.
- **Not a guarantee of security.** Zero findings does not mean zero bugs. It means the current rules didn't find anything.
- **Not an AI that "understands" your contract.** The AI only sees the small snippet we send it. It doesn't understand your full protocol, business logic, token economics, or deployment context.

### 💡 What this tool IS

- 🏃 **A fast first pass.** Catches common patterns that developers miss during development.
- 📚 **An educational tool.** The explanations teach developers about security patterns.
- 🚧 **A CI/CD gate.** Can catch obvious issues before code review.
- 🔍 **A starting point.** Findings from this tool are good starting points for deeper manual review.

### Trust matrix

| Component | Deterministic? | Can hallucinate? | Trust level |
|-----------|---------------|-----------------|-------------|
| 📝 Parser (AST extraction) | ✅ Yes | ❌ No | High — but regex-based, may miss things |
| 📏 Rule engine (pattern detection) | ✅ Yes | ❌ No | High — patterns are verifiable |
| 📍 Finding data (line numbers, snippets) | ✅ Yes | ❌ No | High — directly from source |
| 🤖 AI explanation (GPT-5) | ❌ No | ⚠️ Slightly | Medium — usually correct for known vulns |
| 📝 Fallback templates | ✅ Yes | ❌ No | High — hand-written by humans |

---

## 📊 Data Flow Diagram

```
   oaudit analyze contract.sol
              │
              ▼
   ┌─────────────────────┐
   │ ⚙️ Load config      │  openaudit/config.py
   │  (.env → env vars)  │  python-dotenv
   └──────────┬──────────┘
              │ OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL
              ▼
   ┌─────────────────────┐
   │ 📄 Load .sol file   │  openaudit/utils/loader.py
   │  (read from disk)   │
   └──────────┬──────────┘
              │ ContractSource (path, content, lines)
              ▼
   ┌─────────────────────┐
   │ 📝 Parse to AST     │  openaudit/analyzer/parser.py
   │  (regex on each     │
   │   line, extract     │  NO network call
   │   contracts,        │  NO AI
   │   functions,        │
   │   calls, writes)    │
   └──────────┬──────────┘
              │ list[ASTNode]
              ▼
   ┌─────────────────────┐
   │ 📏 Run Rules        │  openaudit/analyzer/engine.py
   │                     │  openaudit/rules/reentrancy.py
   │  For each rule:     │  openaudit/rules/unchecked_call.py
   │    rule.run(ast) →  │
   │    list[Finding]    │  NO network call
   │                     │  NO AI
   └──────────┬──────────┘
              │ list[Finding]  ← This IS the audit result
              ▼
   ┌─────────────────────┐
   │ 🤖 Explain Findings │  openaudit/ai/explainer.py
   │                     │  openaudit/ai/provider.py
   │  IF OPENAI_API_KEY: │
   │    Send snippet +   │──── POST api.openai.com/v1/chat/completions
   │    finding to GPT   │     (only snippet + finding, NOT full file)
   │                     │
   │  Model fail?        │──── Retry with gpt-4o-mini (fallback model)
   │  API fail?          │──── Use FallbackProvider templates (no network)
   │                     │
   │  IF no key / --no-ai│
   │    Use hardcoded    │  ← No network call
   │    templates        │
   └──────────┬──────────┘
              │ dict[int, str]  (finding_index → explanation text)
              ▼
   ┌─────────────────────┐
   │ 🖥️ Format Output   │  openaudit/reports/terminal.py
   │                     │  openaudit/reports/json_report.py
   │  Terminal (Rich)    │
   │  or JSON            │
   └─────────────────────┘
```

---

## 📂 Full Code Walkthrough

### `openaudit/config.py` — ⚙️ Centralized Configuration

Loads `.env` at import time via `python-dotenv`. Exposes:
- `OPENAI_API_KEY` — from env or `.env`
- `OPENAI_BASE_URL` — custom endpoint (Azure, local proxy, etc.)
- `OPENAI_MODEL` — defaults to `gpt-5-mini`
- `FALLBACK_MODEL` — hardcoded `gpt-4o-mini`
- `has_api_key()` — boolean check used by `Explainer`
- `effective_base_url()` — display helper for `doctor` command

### `openaudit/utils/types.py` — 📦 Domain Models

Defines the data structures everything else uses:

- **`Severity`** — Enum: critical, high, medium, low, info
- **`Finding`** — One vulnerability instance (rule_id, title, severity, line, description, snippet, metadata)
- **`AuditResult`** — All findings for one file + AI explanations
- **`ContractSource`** — The loaded .sol file (path, content, list of lines)

### `openaudit/analyzer/parser.py` — 📝 Solidity Parser

Scans each line of the .sol file with regexes:
1. Tracks `contract` / `function` scope via brace depth
2. Inside each function, classifies lines as `EXTERNAL_CALL` or `STATE_WRITE`
3. Builds a tree: Contract → Function → [calls, writes]

### `openaudit/rules/base.py` — 📏 Rule Interface

Abstract base class. Every rule must implement:
```python
def run(self, ast: list[ASTNode], source: ContractSource) -> list[Finding]
```

### `openaudit/rules/registry.py` — 🗂️ Rule Discovery

The `@register` decorator adds rules to a global dict. The engine calls `get_enabled_rules()` which imports all rule modules (triggering registration) and returns instances.

### `openaudit/rules/reentrancy.py` — 🔁 Reentrancy Detector

For each function: if any external call line < any state write line → finding.

### `openaudit/rules/unchecked_call.py` — ⚠️ Unchecked Call Detector

For each `.call()` inside a function: check if the line has `(bool success,` or `require(`. If not → finding.

### `openaudit/ai/prompts.py` — 💬 Prompt Templates

Contains the system prompt ("you are a security auditor") and the per-finding template that formats the vulnerability data into a prompt.

### `openaudit/ai/provider.py` — 🤖 LLM Provider Abstraction

- `LLMProvider` — abstract interface
- `OpenAIProvider` — calls `client.chat.completions.create()`, handles GPT-5 vs GPT-4o parameter differences, implements model fallback
- `FallbackProvider` — returns hardcoded templates per rule_id

### `openaudit/ai/explainer.py` — 🛡️ Explanation Orchestrator

Picks the right provider based on `config`. Wraps every call in try/except — if the API fails for any reason, silently falls back to `FallbackProvider`.

### `openaudit/cli/main.py` — 💻 CLI Entry Point

Typer commands:
- `analyze` — audit a single `.sol` file
- `scan` — audit all `.sol` files in a directory
- `doctor` — diagnose AI provider configuration
- `version` — print version

### `openaudit/reports/terminal.py` — 🖥️ Terminal Formatter

Uses Rich library to render colored, paneled output with severity icons.

### `openaudit/reports/json_report.py` — 📄 JSON Formatter

Serializes `AuditResult` to JSON for CI/CD pipelines.

---

## 📝 Summary

**Q: Do we send .sol contracts to OpenAI to see if they're bad?**
❌ No. The local static analysis engine detects issues. OpenAI only receives small code snippets from already-identified findings, and its only job is to write a human-readable explanation.

**Q: Where does the "AI Explanation" come from?**
If you have an `OPENAI_API_KEY` set: from the OpenAI chat completions API (default model: `gpt-5-mini`), based on a prompt containing the finding data and code snippet. If you don't: from hardcoded templates in `FallbackProvider` — no network call at all.

**Q: How do we actually audit?**
Regex-based parsing → AST → deterministic pattern matching rules. External call before state write = reentrancy finding. Unchecked `.call()` return = unchecked-call finding. Pure local computation.

**Q: What if the AI model fails?**
Two layers of fallback: (1) retry with `gpt-4o-mini`, (2) use offline templates. The tool never crashes.

**Q: Can we trust it?**
Trust the detection (it's deterministic and verifiable), but don't treat it as comprehensive. It catches common patterns. It will miss complex vulnerabilities. It's a first pass, not a full audit.
