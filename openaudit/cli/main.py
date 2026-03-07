"""CLI entry point for OpenAudit AI.

Provides the `oaudit` command with subcommands for analyzing
individual contracts, scanning directories, and diagnostics.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

import openaudit
from openaudit import config
from openaudit.ai.explainer import Explainer
from openaudit.ai.provider import OpenAIProvider
from openaudit.analyzer.engine import AnalysisEngine
from openaudit.reports.json_report import results_to_json
from openaudit.reports.terminal import print_results, print_summary
from openaudit.utils.loader import discover_solidity_files, load_solidity_file
from openaudit.utils.types import AuditResult

app = typer.Typer(
    name="oaudit",
    help="OpenAudit AI — AI-powered smart contract security auditor.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()
engine = AnalysisEngine()


@app.command()
def analyze(
    file: Path = typer.Argument(..., help="Path to a Solidity (.sol) file.", exists=True),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results as JSON."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI-powered explanations."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model to use."),
) -> None:
    """Analyze a single Solidity file for vulnerabilities."""
    result = _audit_file(file, use_ai=not no_ai, model=model)

    if json_output:
        typer.echo(results_to_json([result]))
    else:
        print_results(result)


@app.command()
def scan(
    directory: Path = typer.Argument(..., help="Directory to scan for .sol files.", exists=True),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results as JSON."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI-powered explanations."),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model to use."),
) -> None:
    """Scan a directory for Solidity files and audit each one."""
    sol_files = discover_solidity_files(directory)

    if not sol_files:
        console.print(f"[yellow]No .sol files found in {directory}[/yellow]")
        raise typer.Exit(0)

    console.print(f"Found [bold]{len(sol_files)}[/bold] Solidity file(s) in {directory}\n")

    results: list[AuditResult] = []
    for sol_file in sol_files:
        result = _audit_file(sol_file, use_ai=not no_ai, model=model)
        results.append(result)

    if json_output:
        typer.echo(results_to_json(results))
    else:
        for result in results:
            print_results(result)
        print_summary(results)


@app.command()
def version() -> None:
    """Show the OpenAudit AI version."""
    console.print(f"OpenAudit AI v{openaudit.__version__}")


@app.command()
def doctor() -> None:
    """Diagnose AI provider configuration."""
    has_key = config.has_api_key()
    fallback_active = not has_key

    console.print()
    console.print("[bold]OpenAudit AI — Configuration Diagnostic[/bold]")
    console.print()
    console.print(f"  AI Provider:    [cyan]OpenAI[/cyan]")
    console.print(f"  Model:          [cyan]{config.OPENAI_MODEL}[/cyan]")

    if has_key:
        console.print(f"  API Key:        [green]detected[/green]")
    else:
        console.print(f"  API Key:        [red]not set[/red]")

    console.print(f"  Base URL:       [cyan]{config.effective_base_url()}[/cyan]")

    if fallback_active:
        console.print(f"  Fallback Mode:  [yellow]active[/yellow] (template-based explanations)")
    else:
        console.print(f"  Fallback Mode:  [green]disabled[/green]")

    console.print()

    if not has_key:
        console.print(
            "[dim]Tip: Add OPENAI_API_KEY to .env or export it to enable AI explanations.[/dim]"
        )
        console.print()


def _audit_file(
    file: Path,
    use_ai: bool = True,
    model: str | None = None,
) -> AuditResult:
    """Run the full audit pipeline on a single file."""
    try:
        source = load_solidity_file(file)
    except (FileNotFoundError, ValueError) as exc:
        return AuditResult(file=str(file), error=str(exc))

    findings = engine.analyze(source)

    if model:
        explainer = Explainer(provider=OpenAIProvider(model=model))
    else:
        explainer = Explainer(use_ai=use_ai)

    ai_explanations = explainer.explain_all(findings)

    return AuditResult(
        file=str(file),
        findings=findings,
        ai_explanations=ai_explanations,
    )


if __name__ == "__main__":
    app()
