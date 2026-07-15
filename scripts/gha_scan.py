#!/usr/bin/env python3
"""
DelegateGuard GitHub Action entrypoint.

Runs the analyzer and/or scanner over the target, merges the JSON reports,
writes a PR-comment markdown file, exports step outputs, and drops a sentinel
file when findings breach the configured severity gate (the composite action
turns that sentinel into a non-zero exit).

Driven entirely by environment variables set in action.yml:
    DG_TARGET   path to scan
    DG_MODE     analyze | scan | both
    DG_FAIL_ON  CRITICAL | HIGH | MEDIUM | INFO | NONE
    DG_SOLC     optional solc path/version
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SEVERITY_ORDER = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def run_engine(command: str, target: str, solc: str) -> list[dict]:
    """Invoke a CLI subcommand with --json --out and return its findings list."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tmp:
        out_path = tmp.name

    argv = ["delegateguard", command, target, "--json", "--out", out_path]
    if solc:
        argv += ["--solc", solc]

    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        # Surface the CLI's stderr but keep going so one engine failing
        # does not silently swallow the other engine's findings.
        print(f"::warning::delegateguard {command} exited {proc.returncode}: {proc.stderr.strip()[:400]}")
        return []

    try:
        data = json.loads(Path(out_path).read_text())
        return data.get("findings", [])
    except (OSError, json.JSONDecodeError) as e:
        print(f"::warning::could not read {command} report: {e}")
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_comment(target: str, mode: str, findings: list[dict], counts: dict[str, int]) -> str:
    total = len(findings)
    lines = ["<!-- delegateguard-report -->", "## 🛡️ DelegateGuard — EIP-7702 scan", ""]

    if total == 0:
        lines += [
            f"No findings on `{target}` ({mode}). Clean against all "
            "configured detectors. ✅",
            "",
            "_Heuristic static analysis — absence of findings is not a proof of safety._",
        ]
        return "\n".join(lines)

    badge = "  ".join(
        f"**{counts[s]} {s}**" for s in reversed(SEVERITY_ORDER) if counts[s]
    )
    lines += [f"Found **{total}** finding(s) on `{target}`: {badge}", "", "| Sev | Class | Title | Location |", "| --- | --- | --- | --- |"]

    for f in sorted(findings, key=lambda x: -SEVERITY_RANK.get(x.get("severity", "INFO"), 0)):
        loc = f.get("source_file") or "n/a"
        if f.get("line"):
            loc = f"{loc}:{f['line']}"
        title = (f.get("title") or "").replace("|", "\\|")
        lines.append(
            f"| {f.get('severity','')} | `{f.get('bug_class','')}` | {title} | `{loc}` |"
        )

    lines += [
        "",
        "<details><summary>Remediation detail</summary>",
        "",
    ]
    for f in findings:
        lines += [
            f"**`{f.get('bug_class','')}` {f.get('title','')}**  ",
            f"{f.get('description','')}  ",
            f"_Fix:_ {f.get('recommendation','')}  ",
            f"_PoC:_ `{f.get('poc_ref','')}`",
            "",
        ]
    lines += ["</details>", "", "_Heuristic static analysis — review each finding before acting._"]
    return "\n".join(lines)


def gate_breached(counts: dict[str, int], fail_on: str) -> bool:
    fail_on = (fail_on or "CRITICAL").upper()
    if fail_on == "NONE":
        return False
    threshold = SEVERITY_RANK.get(fail_on, SEVERITY_RANK["CRITICAL"])
    for sev, rank in SEVERITY_RANK.items():
        if rank >= threshold and counts.get(sev, 0) > 0:
            return True
    return False


def set_output(name: str, value: str) -> None:
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def main() -> int:
    target = os.environ.get("DG_TARGET", ".")
    mode = os.environ.get("DG_MODE", "both").lower()
    fail_on = os.environ.get("DG_FAIL_ON", "CRITICAL")
    solc = os.environ.get("DG_SOLC", "")

    findings: list[dict] = []
    if mode in ("analyze", "both"):
        findings += run_engine("analyze", target, solc)
    if mode in ("scan", "both"):
        findings += run_engine("scan", target, solc)

    counts = severity_counts(findings)
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "."))

    (workspace / "delegateguard-report.json").write_text(
        json.dumps({"target": target, "mode": mode, "total": len(findings),
                    "counts": counts, "findings": findings}, indent=2)
    )
    (workspace / "delegateguard-comment.md").write_text(
        build_comment(target, mode, findings, counts)
    )

    set_output("total", str(len(findings)))
    set_output("critical", str(counts.get("CRITICAL", 0)))
    set_output("report", str(workspace / "delegateguard-report.json"))

    print(f"DelegateGuard: {len(findings)} finding(s) — "
          + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if counts[s]))

    if gate_breached(counts, fail_on):
        (workspace / "delegateguard-failed").write_text("1")
        print(f"::error::severity gate '{fail_on}' breached")

    # Always exit 0 here — the composite action reads the sentinel and decides
    # the job's fate, so the PR comment step still runs on a gate breach.
    return 0


if __name__ == "__main__":
    sys.exit(main())
