"""Tests for the CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from openaudit.cli.main import app

runner = CliRunner()

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "OpenAudit AI" in result.stdout


def test_analyze_vulnerable_contract():
    vuln_file = EXAMPLES_DIR / "vulnerable_bank.sol"
    if not vuln_file.exists():
        return
    result = runner.invoke(app, ["analyze", str(vuln_file), "--no-ai"])
    assert result.exit_code == 0
    assert "Reentrancy" in result.stdout or "reentrancy" in result.stdout.lower()


def test_analyze_json_output():
    vuln_file = EXAMPLES_DIR / "vulnerable_bank.sol"
    if not vuln_file.exists():
        return
    result = runner.invoke(app, ["analyze", str(vuln_file), "--no-ai", "--json"])
    assert result.exit_code == 0
    assert '"rule_id"' in result.stdout


def test_analyze_safe_contract():
    safe_file = EXAMPLES_DIR / "safe_bank.sol"
    if not safe_file.exists():
        return
    result = runner.invoke(app, ["analyze", str(safe_file), "--no-ai"])
    assert result.exit_code == 0
    assert "No vulnerabilities detected" in result.stdout


def test_scan_directory():
    if not EXAMPLES_DIR.exists():
        return
    result = runner.invoke(app, ["scan", str(EXAMPLES_DIR), "--no-ai"])
    assert result.exit_code == 0
    assert "Audit Summary" in result.stdout


def test_analyze_nonexistent_file():
    result = runner.invoke(app, ["analyze", "/tmp/nonexistent_xyz.sol"])
    assert result.exit_code != 0


def test_doctor_command():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "AI Provider" in result.stdout
    assert "Model" in result.stdout
    assert "API Key" in result.stdout
    assert "Base URL" in result.stdout
    assert "Fallback Mode" in result.stdout


def test_doctor_shows_detected_key(monkeypatch):
    monkeypatch.setattr("openaudit.config.OPENAI_API_KEY", "sk-test")
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "detected" in result.stdout


def test_doctor_shows_missing_key(monkeypatch):
    monkeypatch.setattr("openaudit.config.OPENAI_API_KEY", None)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "not set" in result.stdout
