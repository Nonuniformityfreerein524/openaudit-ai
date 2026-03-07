"""Rich terminal output for audit results."""

from __future__ import annotations

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from openaudit.utils.types import AuditResult, Severity

console = Console()

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "\u2622\ufe0f ",
    Severity.HIGH: "\u26a0\ufe0f ",
    Severity.MEDIUM: "\u26a0\ufe0f ",
    Severity.LOW: "\u2139\ufe0f ",
    Severity.INFO: "\U0001f4ac ",
}


def print_results(result: AuditResult) -> None:
    """Print a full audit result to the terminal with rich formatting."""
    console.print()

    if result.error:
        console.print(Panel(f"[red]Error:[/red] {result.error}", title=result.file))
        return

    if not result.findings:
        console.print(
            Panel(
                "[green]No vulnerabilities detected.[/green]",
                title=f"\u2705 {result.file}",
            )
        )
        return

    header = Text(f" {result.file} ", style="bold white on blue")
    console.print(header)
    console.print(
        f"  Found [bold]{len(result.findings)}[/bold] potential issue(s)\n"
    )

    for idx, finding in enumerate(result.findings):
        icon = _SEVERITY_ICONS.get(finding.severity, "")
        style = _SEVERITY_STYLES.get(finding.severity, "")

        title_line = f"{icon}{finding.title}"
        console.print(f"[{style}]{title_line}[/{style}]")
        console.print(f"  [dim]Severity:[/dim] [{style}]{finding.severity.value.upper()}[/{style}]")

        if finding.line:
            console.print(f"  [dim]Location:[/dim] line {finding.line}")

        console.print(f"  [dim]Rule:[/dim] {finding.rule_id}")
        console.print()

        if finding.snippet:
            console.print(Panel(finding.snippet, title="Code", border_style="dim"))

        console.print(f"  {finding.description}")
        console.print()

        explanation = result.ai_explanations.get(idx)
        if explanation:
            console.print(Panel(Markdown(explanation), title="AI Explanation", border_style="green"))

        console.print("[dim]" + "\u2500" * 60 + "[/dim]")
        console.print()


def print_summary(results: list[AuditResult]) -> None:
    """Print a brief summary across multiple files."""
    total_findings = sum(len(r.findings) for r in results)
    total_files = len(results)
    errors = sum(1 for r in results if r.error)

    console.print()
    console.print(f"[bold]Audit Summary[/bold]")
    console.print(f"  Files scanned:  {total_files}")
    console.print(f"  Issues found:   {total_findings}")
    if errors:
        console.print(f"  Errors:         [red]{errors}[/red]")
    console.print()
