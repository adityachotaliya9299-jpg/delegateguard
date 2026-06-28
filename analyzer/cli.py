#!/usr/bin/env python3
"""
DelegateGuard CLI

Usage:
    delegateguard analyze <target> [options]   # DC-01..DC-08
    delegateguard scan    <target> [options]   # PA-01..PA-05
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "INFO":     "dim",
}
SEVERITY_ICON = {
    "CRITICAL": "[red]CRIT[/red]",
    "HIGH":     "[yellow]HIGH[/yellow]",
    "MEDIUM":   "[yellow]MED [/yellow]",
    "INFO":     "[dim]INFO[/dim]",
}


@click.group()
def cli():
    """DelegateGuard — EIP-7702 security analyzer."""
    pass


# ---------------------------------------------------------------------------
# ANALYZE command — Delegate contract analyzer (Engine 1, DC-01..DC-08)
# ---------------------------------------------------------------------------

@cli.command("analyze")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json",     "output_json", is_flag=True)
@click.option("--severity", "-s", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "INFO"],
                                case_sensitive=False))
@click.option("--solc",     default=None)
@click.option("--out",      default=None, type=click.Path())
def analyze(target: str, output_json: bool, severity: tuple,
            solc: Optional[str], out: Optional[str]):
    """Analyze a delegate contract for EIP-7702-specific bugs (DC-01..DC-08).

    \b
    Examples:
      delegateguard analyze contracts/MyDelegate.sol
      delegateguard analyze contracts/ --severity CRITICAL --severity HIGH
      delegateguard analyze contracts/ --json --out report.json
    """
    _print_banner()

    try:
        from slither import Slither
    except ImportError:
        console.print("[bold red]Error:[/bold red] slither-analyzer not installed.")
        console.print("Run: [cyan]pip install slither-analyzer[/cyan]")
        sys.exit(1)

    # Import here (not at module level) so CLI loads even without detectors present
    from analyzer.detectors import DELEGATE_DETECTORS

    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold]   Delegate-contract analyzer (DC-01..DC-08)")
    console.print(f"[bold]Detectors:[/bold] {len(DELEGATE_DETECTORS)}\n")

    slither = _run_slither(target, solc)
    if slither is None:
        sys.exit(1)

    all_findings = _run_detectors(DELEGATE_DETECTORS, slither)
    all_findings = _filter_and_sort(all_findings, severity)

    _output(all_findings, target, "delegate-analyze", output_json, out)


# ---------------------------------------------------------------------------
# SCAN command — Protocol-assumption scanner (Engine 2, PA-01..PA-05)
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json",     "output_json", is_flag=True)
@click.option("--severity", "-s", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "INFO"],
                                case_sensitive=False))
@click.option("--solc",     default=None)
@click.option("--out",      default=None, type=click.Path())
def scan(target: str, output_json: bool, severity: tuple,
         solc: Optional[str], out: Optional[str]):
    """Scan any Solidity codebase for post-Pectra protocol-assumption bugs (PA-01..PA-05).

    \b
    Examples:
      delegateguard scan contracts/
      delegateguard scan contracts/Pool.sol --severity CRITICAL --severity HIGH
      delegateguard scan contracts/ --json --out scan-report.json
    """
    _print_banner()

    try:
        from slither import Slither  # noqa: F401
    except ImportError:
        console.print("[bold red]Error:[/bold red] slither-analyzer not installed.")
        sys.exit(1)

    from scanner.detectors import SCANNER_DETECTORS

    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold]   Protocol-assumption scanner (PA-01..PA-05)")
    console.print(f"[bold]Detectors:[/bold] {len(SCANNER_DETECTORS)}\n")

    slither = _run_slither(target, solc)
    if slither is None:
        sys.exit(1)

    all_findings = _run_detectors(SCANNER_DETECTORS, slither)
    all_findings = _filter_and_sort(all_findings, severity)

    _output(all_findings, target, "protocol-scan", output_json, out)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _run_slither(target: str, solc: Optional[str]):
    from slither import Slither
    try:
        kwargs = {}
        if solc:
            kwargs["solc"] = solc
        with console.status("[cyan]Running Slither...[/cyan]"):
            return Slither(target, **kwargs)
    except Exception as e:
        console.print(f"[bold red]Slither error:[/bold red] {e}")
        return None


def _run_detectors(detector_classes, slither) -> List:
    findings = []
    with console.status("[cyan]Running detectors...[/cyan]"):
        for cls in detector_classes:
            try:
                findings.extend(cls(slither).run())
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] {cls.__name__} failed: {e}")
    return findings


def _filter_and_sort(findings: List, severity: tuple) -> List:
    if severity:
        sevs = [s.upper() for s in severity]
        findings = [f for f in findings if f.severity.value in sevs]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    findings.sort(key=lambda f: order.get(f.severity.value, 99))
    return findings


def _output(findings: List, target: str, mode: str,
            output_json: bool, out: Optional[str]):
    if output_json or out:
        data = {
            "target":   target,
            "mode":     mode,
            "total":    len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        js = json.dumps(data, indent=2)
        if out:
            Path(out).write_text(js)
            console.print(f"[green]Report written to:[/green] {out}")
        else:
            print(js)
        return
    _print_findings(findings, target)


def _print_banner():
    banner = Text()
    banner.append("DelegateGuard", style="bold cyan")
    banner.append(" — EIP-7702 Security Analyzer", style="dim")
    console.print(Panel(banner, box=box.ROUNDED, padding=(0, 2)))
    console.print()


def _print_findings(findings: List, target: str):
    if not findings:
        console.print(Panel(
            "[bold green]No issues found.[/bold green]",
            title="[bold green]Clean[/bold green]",
            box=box.ROUNDED,
        ))
        return

    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    parts = [
        f"[{SEVERITY_STYLE[s]}]{c} {s}[/{SEVERITY_STYLE[s]}]"
        for s, c in counts.items() if c
    ]
    console.print(Panel(
        f"Found [bold]{len(findings)}[/bold] issue(s): " + "  ".join(parts),
        title="[bold red]Issues Found[/bold red]",
        box=box.ROUNDED,
    ))
    console.print()

    table = Table(box=box.SIMPLE_HEAVY, show_header=True,
                  header_style="bold", padding=(0, 1))
    table.add_column("Sev",      width=6)
    table.add_column("ID",       width=7)
    table.add_column("Contract", width=28)
    table.add_column("Function", width=24)
    table.add_column("Title",    width=44)

    for f in findings:
        table.add_row(
            SEVERITY_ICON.get(f.severity.value, f.severity.value),
            f.bug_class.value,
            f.contract or "",
            f.function or "",
            f.title,
        )
    console.print(table)
    console.print()

    for i, f in enumerate(findings, 1):
        sev_style = SEVERITY_STYLE.get(f.severity.value, "")
        loc = f"  [dim]{f.source_file}:{f.line}[/dim]" if f.source_file and f.line else ""
        console.print(
            f"[bold]{i}. [{sev_style}]{f.severity.value}[/{sev_style}] "
            f"[cyan]{f.bug_class.value}[/cyan] — {f.title}[/bold]{loc}"
        )
        console.print(
            f"   [dim]Contract:[/dim] {f.contract}"
            + (f"  [dim]Function:[/dim] {f.function}" if f.function else "")
        )
        console.print(f"   {f.description}")
        console.print(f"   [bold green]Fix:[/bold green] {f.recommendation}")
        console.print(f"   [dim]PoC: {f.poc_ref}[/dim]")
        console.print()


def main():
    cli()


if __name__ == "__main__":
    main()