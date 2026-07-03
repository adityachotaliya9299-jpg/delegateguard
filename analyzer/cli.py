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


# ---------------------------------------------------------------------------
# HARNESS command — PoC / invariant harness generator (Engine 3, Phase 4)
# ---------------------------------------------------------------------------

@cli.command("harness")
@click.argument("target", type=click.Path(exists=True))
@click.option("--out", "-o", default="harnesses/",
              show_default=True, type=click.Path(),
              help="Output directory for generated .t.sol files.")
@click.option("--severity", "-s", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "INFO"],
                                case_sensitive=False),
              help="Only generate harnesses for these severities.")
@click.option("--bug",  "-b", multiple=True,
              help="Only generate harnesses for specific bug classes (e.g. DC-07 PA-04).")
@click.option("--solc", default=None, help="Path to solc binary.")
@click.option("--mode", default="both",
              type=click.Choice(["analyze", "scan", "both"], case_sensitive=False),
              help="Run analyzer (DC), scanner (PA), or both.")
def harness(target: str, out: str, severity: tuple, bug: tuple,
            solc: Optional[str], mode: str):
    """
    Generate Foundry test harnesses for every finding in TARGET.

    Runs the analyzer + scanner (or just one), collects all findings,
    and writes a .t.sol scaffold for each one into --out.

    The generated tests:
      - compile immediately with forge test (no manual edits needed)
      - have RED tests (exploit path) pre-stubbed with TODO markers
      - have GREEN tests (fix path) pre-stubbed
      - include the exact source file and line from the finding

    \b
    Examples:
      delegateguard harness contracts/MyDelegate.sol
      delegateguard harness contracts/ --out audit-harnesses/ --severity CRITICAL --severity HIGH
      delegateguard harness contracts/MyDelegate.sol --bug DC-07 --bug DC-05
      delegateguard harness contracts/ --mode analyze
    """
    _print_banner()

    try:
        from slither import Slither  # noqa: F401
    except ImportError:
        console.print("[bold red]Error:[/bold red] slither-analyzer not installed.")
        sys.exit(1)

    from harness.generator import HarnessGenerator

    console.print(f"[bold]Target:[/bold]  {target}")
    console.print(f"[bold]Mode:[/bold]    {mode}")
    console.print(f"[bold]Output:[/bold]  {out}\n")

    # Collect findings from analyzer and/or scanner
    all_findings = []

    slither = _run_slither(target, solc)
    if slither is None:
        sys.exit(1)

    if mode in ("analyze", "both"):
        from analyzer.detectors import DELEGATE_DETECTORS
        findings = _run_detectors(DELEGATE_DETECTORS, slither)
        all_findings.extend(findings)
        console.print(f"[cyan]Analyzer:[/cyan] {len(findings)} findings")

    if mode in ("scan", "both"):
        from scanner.detectors import SCANNER_DETECTORS
        findings = _run_detectors(SCANNER_DETECTORS, slither)
        all_findings.extend(findings)
        console.print(f"[cyan]Scanner:[/cyan]  {len(findings)} findings")

    # Apply filters
    if severity:
        sevs = [s.upper() for s in severity]
        all_findings = [f for f in all_findings if f.severity.value in sevs]

    if bug:
        bugs = [b.upper() for b in bug]
        all_findings = [f for f in all_findings if f.bug_class.value.upper() in bugs]

    # Deduplicate: one harness per (bug_class, contract, function)
    seen: set = set()
    unique_findings = []
    for f in all_findings:
        key = (f.bug_class, f.contract, f.function)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    if not unique_findings:
        console.print(Panel(
            "[bold yellow]No findings matched the filters.[/bold yellow]\n"
            "Try removing --severity or --bug filters.",
            box=box.ROUNDED,
        ))
        return

    console.print(f"\n[bold]Generating harnesses for {len(unique_findings)} finding(s)...[/bold]\n")

    # Generate harnesses
    gen = HarnessGenerator()
    generated = []
    skipped   = []

    for f in unique_findings:
        try:
            out_path = gen.write(f, output_dir=out)
            generated.append((f, out_path))
        except (ValueError, FileNotFoundError) as e:
            skipped.append((f, str(e)))

    # Summary table
    if generated:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True,
                      header_style="bold", padding=(0, 1))
        table.add_column("Bug",      width=7)
        table.add_column("Contract", width=28)
        table.add_column("Function", width=20)
        table.add_column("File",     width=50)

        for f, path in generated:
            table.add_row(
                f.bug_class.value,
                f.contract or "",
                f.function or "",
                str(path),
            )
        console.print(table)

    if skipped:
        console.print(f"\n[yellow]Skipped {len(skipped)} finding(s):[/yellow]")
        for f, reason in skipped:
            console.print(f"  [dim]{f.bug_class.value} {f.contract}: {reason}[/dim]")

    console.print(Panel(
        f"[bold green]Generated {len(generated)} harness(es)[/bold green] in [cyan]{out}[/cyan]\n\n"
        f"[dim]Next steps:\n"
        f"  1. Copy generated files to your Foundry project test/ directory\n"
        f"  2. Fill in contract imports and TODO placeholders\n"
        f"  3. Run: forge test --match-contract <HarnessName> -vv[/dim]",
        title="[bold green]Done[/bold green]",
        box=box.ROUNDED,
    ))


# ---------------------------------------------------------------------------
# MONITOR command — On-chain delegation monitor (Engine 4, Phase 6)
# ---------------------------------------------------------------------------

@cli.command("monitor")
@click.option("--rpc",     required=True, envvar="ETH_RPC_URL",
              help="Ethereum JSON-RPC endpoint URL. Also reads ETH_RPC_URL env var.")
@click.option("--chain",   default=1, show_default=True, type=int,
              help="Chain ID (1=mainnet, 11155111=Sepolia, 42161=Arbitrum).")
@click.option("--start-block", default=None, type=int,
              help="Start scanning from this block (default: latest).")
@click.option("--poll",    default=12.0, show_default=True, type=float,
              help="Poll interval in seconds.")
@click.option("--check",   default=None,
              help="One-shot: check a specific delegate address and exit.")
@click.option("--registry-path", default=None,
              help="Path to persist the delegate registry JSON.")
@click.option("--verbose", is_flag=True, help="Enable debug logging.")
def monitor(rpc: str, chain: int, start_block: Optional[int],
            poll: float, check: Optional[str],
            registry_path: Optional[str], verbose: bool):
    """
    Monitor Ethereum for EIP-7702 delegations in real time.

    Indexes type-4 transactions, cross-references delegate addresses
    against the known-malicious registry, and alerts on suspicious activity.

    \b
    Examples:
      # Watch mainnet live
      delegateguard monitor --rpc https://mainnet.infura.io/v3/KEY

      # Watch Sepolia testnet
      delegateguard monitor --rpc https://sepolia.infura.io/v3/KEY --chain 11155111

      # Use env var for RPC
      export ETH_RPC_URL=https://mainnet.infura.io/v3/KEY
      delegateguard monitor

      # One-shot: check if an address is malicious
      delegateguard monitor --rpc $ETH_RPC_URL --check 0xDEAD...

      # Start from a specific block
      delegateguard monitor --rpc $ETH_RPC_URL --start-block 21000000
    """
    _print_banner()

    try:
        from monitor.src import DelegateGuardMonitor
    except ImportError as e:
        console.print(f"[bold red]Error:[/bold red] monitor module not found: {e}")
        console.print("Ensure you are running from the delegateguard root directory.")
        sys.exit(1)

    mon = DelegateGuardMonitor(
        rpc_url=rpc,
        chain_id=chain,
        start_block=start_block,
        registry_path=registry_path,
        poll_interval=poll,
        verbose=verbose,
    )

    # One-shot address check
    if check:
        console.print(f"[bold]Checking delegate address:[/bold] {check}\n")
        result = mon.check_address(check)

        status = result.get("status", "unknown")
        status_color = {
            "malicious":  "bold red",
            "suspicious": "bold yellow",
            "safe":       "bold green",
            "unknown":    "dim",
            "revoked":    "dim",
        }.get(status, "white")

        console.print(Panel(
            f"[{status_color}]{status.upper()}[/{status_color}]\n\n"
            + (f"Name: {result['name']}\n" if result.get("name") else "")
            + (f"Notes: {result['notes']}\n" if result.get("notes") else "")
            + (f"Risk signals: {', '.join(result['risk_signals'])}" if result.get("risk_signals") else "No risk signals"),
            title=f"[bold]{check[:20]}...[/bold]",
            box=box.ROUNDED,
        ))
        return

    # Start live monitor
    console.print(Panel(
        f"[bold]RPC:[/bold]    {rpc[:50]}...\n"
        f"[bold]Chain:[/bold]  {chain}\n"
        f"[bold]Poll:[/bold]   every {poll}s\n"
        f"[bold]Registry:[/bold] {mon.registry.stats()['total']} known delegates "
        f"({mon.registry.stats().get('malicious', 0)} malicious)\n\n"
        "[dim]Ctrl+C to stop[/dim]",
        title="[bold cyan]DelegateGuard Monitor Starting[/bold cyan]",
        box=box.ROUNDED,
    ))

    try:
        mon.start()
    except KeyboardInterrupt:
        console.print("\n[dim]Monitor stopped.[/dim]")
        status = mon.status()
        console.print(Panel(
            f"Blocks scanned: {status['indexer']['total_blocks']}\n"
            f"Events found:   {status['indexer']['total_events']}\n"
            f"Alerts raised:  {status['alerts']['total']} "
            f"({status['alerts'].get('CRITICAL', 0)} critical, "
            f"{status['alerts'].get('WARNING', 0)} warnings)",
            title="[bold]Session summary[/bold]",
            box=box.ROUNDED,
        ))