#!/usr/bin/env python3
"""
DelegateGuard CLI : Delegate Contract Analyzer (Engine 1)

Usage:
    delegateguard analyze <target> [options]

Examples:
    delegateguard analyze contracts/MyDelegate.sol
    delegateguard analyze contracts/ --json
    delegateguard analyze contracts/MyDelegate.sol --severity CRITICAL HIGH
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


# ---------------------------------------------------------------------------
# Severity colours for the terminal output
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """DelegateGuard — EIP-7702 delegate contract security analyzer."""
    pass


@cli.command("analyze")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json",     "output_json", is_flag=True, help="Output findings as JSON.")
@click.option("--severity", "-s", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "INFO"], case_sensitive=False),
              help="Filter output to these severities (repeatable).")
@click.option("--solc",     default=None,  help="Path to solc binary.")
@click.option("--out",      default=None,  type=click.Path(), help="Write JSON report to file.")
def analyze(target: str, output_json: bool, severity: tuple,
            solc: Optional[str], out: Optional[str]):
    """
    Analyze a delegate contract (or directory) for EIP-7702-specific bugs.

    TARGET can be a .sol file or a directory containing Solidity files.
    """
    _print_banner()

    try:
        from slither import Slither
    except ImportError:
        console.print("[bold red]Error:[/bold red] slither-analyzer not installed.")
        console.print("Run: [cyan]pip install slither-analyzer[/cyan]")
        sys.exit(1)

    from .detectors import DELEGATE_DETECTORS

    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Detectors:[/bold] {len(DELEGATE_DETECTORS)} (DC-01 through DC-08)\n")

    # Run Slither
    try:
        kwargs = {}
        if solc:
            kwargs["solc"] = solc
        with console.status("[cyan]Running Slither...[/cyan]"):
            slither = Slither(target, **kwargs)
    except Exception as e:
        console.print(f"[bold red]Slither error:[/bold red] {e}")
        sys.exit(1)

    # Run all detectors
    all_findings = []
    with console.status("[cyan]Running DelegateGuard detectors...[/cyan]"):
        for detector_cls in DELEGATE_DETECTORS:
            try:
                detector = detector_cls(slither)
                findings = detector.run()
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] detector {detector_cls.__name__} failed: {e}")

    # Filter by severity if requested
    filter_sevs = [s.upper() for s in severity]
    if filter_sevs:
        all_findings = [f for f in all_findings if f.severity.value in filter_sevs]

    # Sort: CRITICAL first, then HIGH, MEDIUM, INFO
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f.severity.value, 99))

    # Output
    if output_json or out:
        data = {
            "target":    target,
            "total":     len(all_findings),
            "findings":  [f.to_dict() for f in all_findings],
        }
        json_str = json.dumps(data, indent=2)
        if out:
            Path(out).write_text(json_str)
            console.print(f"[green]Report written to:[/green] {out}")
        else:
            print(json_str)
        return

    _print_findings(all_findings, target)


def _print_banner():
    banner = Text()
    banner.append("DelegateGuard", style="bold cyan")
    banner.append(" — EIP-7702 Delegate Contract Analyzer", style="dim")
    console.print(Panel(banner, box=box.ROUNDED, padding=(0, 2)))
    console.print()


def _print_findings(findings: List, target: str):
    if not findings:
        console.print(Panel(
            "[bold green]No issues found.[/bold green]\n"
            "[dim]Note: This tool covers DC-01 through DC-08 (delegate-contract bugs).\n"
            "For protocol-assumption bugs (PA-01..PA-05), use [cyan]delegateguard scan[/cyan].[/dim]",
            title="[bold green]Clean[/bold green]",
            box=box.ROUNDED,
        ))
        return

    # Summary counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    summary_parts = []
    for sev, count in counts.items():
        if count:
            style = SEVERITY_STYLE[sev]
            summary_parts.append(f"[{style}]{count} {sev}[/{style}]")

    console.print(Panel(
        f"Found [bold]{len(findings)}[/bold] issue(s): " + "  ".join(summary_parts),
        title=f"[bold red]Issues Found[/bold red]",
        box=box.ROUNDED,
    ))
    console.print()

    # Findings table
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
    )
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

    # Detailed findings
    for i, f in enumerate(findings, 1):
        sev_style = SEVERITY_STYLE.get(f.severity.value, "")
        loc = ""
        if f.source_file and f.line:
            loc = f"  [dim]{f.source_file}:{f.line}[/dim]"

        console.print(f"[bold]{i}. [{sev_style}]{f.severity.value}[/{sev_style}] "
                      f"[cyan]{f.bug_class.value}[/cyan] — {f.title}[/bold]{loc}")
        console.print(f"   [dim]Contract:[/dim] {f.contract}"
                      + (f"  [dim]Function:[/dim] {f.function}" if f.function else ""))
        console.print(f"   {f.description}")
        console.print(f"   [bold green]Fix:[/bold green] {f.recommendation}")
        console.print(f"   [dim]PoC: {f.poc_ref}[/dim]")
        console.print()


def main():
    cli()


if __name__ == "__main__":
    main()


# ---------------------------------------------------------------------------
# SCAN command — Protocol-assumption scanner (Engine 2, Phase 3)
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.argument("target", type=click.Path(exists=True))
@click.option("--json",     "output_json", is_flag=True, help="Output findings as JSON.")
@click.option("--severity", "-s", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "INFO"], case_sensitive=False),
              help="Filter output to these severities.")
@click.option("--solc",     default=None, help="Path to solc binary.")
@click.option("--out",      default=None, type=click.Path(), help="Write JSON report to file.")
def scan(target: str, output_json: bool, severity: tuple,
         solc: Optional[str], out: Optional[str]):
    """
    Scan any Solidity codebase for post-Pectra protocol-assumption bugs (PA-01..PA-05).

    TARGET can be a .sol file or a directory.

    Examples:
        delegateguard scan contracts/
        delegateguard scan contracts/Pool.sol --severity CRITICAL HIGH
        delegateguard scan contracts/ --json --out scan-report.json
    """
    _print_banner()

    try:
        from slither import Slither
    except ImportError:
        console.print("[bold red]Error:[/bold red] slither-analyzer not installed.")
        sys.exit(1)

    from scanner.detectors import SCANNER_DETECTORS

    console.print(f"[bold]Target:[/bold] {target}")
    console.print(f"[bold]Mode:[/bold] Protocol-assumption scanner (PA-01..PA-05)")
    console.print(f"[bold]Detectors:[/bold] {len(SCANNER_DETECTORS)}\n")

    try:
        kwargs = {}
        if solc:
            kwargs["solc"] = solc
        with console.status("[cyan]Running Slither...[/cyan]"):
            slither = Slither(target, **kwargs)
    except Exception as e:
        console.print(f"[bold red]Slither error:[/bold red] {e}")
        sys.exit(1)

    all_findings = []
    with console.status("[cyan]Running DelegateGuard scanner detectors...[/cyan]"):
        for detector_cls in SCANNER_DETECTORS:
            try:
                detector = detector_cls(slither)
                findings = detector.run()
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] {detector_cls.__name__} failed: {e}")

    filter_sevs = [s.upper() for s in severity]
    if filter_sevs:
        all_findings = [f for f in all_findings if f.severity.value in filter_sevs]

    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f.severity.value, 99))

    if output_json or out:
        data = {
            "target":   target,
            "mode":     "protocol-assumption-scan",
            "total":    len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
        json_str = json.dumps(data, indent=2)
        if out:
            Path(out).write_text(json_str)
            console.print(f"[green]Report written to:[/green] {out}")
        else:
            print(json_str)
        return

    _print_findings(all_findings, target)