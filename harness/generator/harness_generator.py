"""
DelegateGuard — Harness Generator (Engine 3)

Takes a Finding (from analyze or scan) and produces a runnable
Foundry test scaffold that sets up the 7702 scenario and asserts
the broken invariant.

The generated .t.sol file:
  - imports forge-std/Test.sol
  - simulates EIP-7702 delegation via vm.etch()
  - has RED tests (proving the exploit) pre-stubbed
  - has GREEN tests (proving the fix) pre-stubbed
  - compiles with no edits (all exploit logic is commented out
    with clear TODO markers so the auditor fills in specifics)
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Optional

from analyzer.core.finding import Finding, BugClass

# Map bug class → template filename
_TEMPLATE_MAP: dict[BugClass, str] = {
    BugClass.DC01_STORAGE_COLLISION:  "DC01_StorageCollision.sol.tpl",
    BugClass.DC02_INIT_FRONTRUN:      "DC02_InitFrontrun.sol.tpl",
    BugClass.DC03_CROSS_CHAIN_REPLAY: "DC03_CrossChainReplay.sol.tpl",
    BugClass.DC04_MISSING_AUTH:       "DC04_MissingAuth.sol.tpl",
    BugClass.DC05_INNER_DELEGATECALL: "DC05_InnerDelegatecall.sol.tpl",
    BugClass.DC06_BATCH_REPLAY:       "DC06_BatchReplay.sol.tpl",
    BugClass.DC07_SWEEPER:            "DC07_Sweeper.sol.tpl",
    BugClass.DC08_SIG_MALLEABILITY:   "DC08_SigMalleability.sol.tpl",
    BugClass.PA01_TX_ORIGIN:          "PA01_TxOrigin.sol.tpl",
    BugClass.PA02_SENDER_ORIGIN_GATE: "PA02_SenderOriginGate.sol.tpl",
    BugClass.PA03_EXTCODESIZE:        "PA03_Extcodesize.sol.tpl",
    BugClass.PA04_EOA_REENTRANCY:     "PA04_EOAReentrancy.sol.tpl",
    BugClass.PA05_EOA_UNIQUENESS:     "PA05_EOAUniqueness.sol.tpl",
}

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


class HarnessGenerator:
    """
    Renders a Foundry test harness from a Finding.

    Usage:
        gen = HarnessGenerator()
        solidity = gen.render(finding)
        gen.write(finding, output_dir="harnesses/")
    """

    def render(self, finding: Finding) -> str:
        """
        Render the harness template for this finding.
        Returns the rendered Solidity source as a string.
        """
        template_file = _TEMPLATE_MAP.get(finding.bug_class)
        if template_file is None:
            raise ValueError(f"No template for bug class: {finding.bug_class}")

        template_path = _TEMPLATES_DIR / template_file
        if not template_path.exists():
            raise FileNotFoundError(f"Template not found: {template_path}")

        template = template_path.read_text()
        return self._substitute(template, finding)

    def write(self, finding: Finding, output_dir: str = ".") -> Path:
        """
        Render and write the harness to output_dir.
        Returns the path to the written file.
        """
        source = self.render(finding)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        filename = self._output_filename(finding)
        out_path = out_dir / filename
        out_path.write_text(source)
        return out_path

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _substitute(self, template: str, finding: Finding) -> str:
        """Replace all {placeholders} in the template with finding values."""
        contract   = finding.contract or "UnknownContract"
        function   = finding.function or "unknownFunction"
        source     = finding.source_file or "unknown.sol"
        line       = str(finding.line or 0)
        test_name  = self._test_contract_name(finding)

        safe_fn = re.sub(r"[^a-zA-Z0-9_]", "_", function)

        replacements = {
            "{contract_name}":    contract,
            "{function_name}":    safe_fn,
            "{source_file}":      source,
            "{line}":             line,
            "{test_contract_name}": test_name,
            # Handle {{}} escaping in templates (for Solidity braces)
        }

        result = template
        for key, val in replacements.items():
            result = result.replace(key, val)

        # Un-escape {{}} → {} for Solidity (after our substitutions are done)
        result = result.replace("{{", "{").replace("}}", "}")

        return result

    def _test_contract_name(self, finding: Finding) -> str:
        """
        Generate a unique, valid Solidity contract name for the test.
        E.g. 'DC07_DC07_SweeperDelegate_execute_Harness'
        """
        bug   = finding.bug_class.value.replace("-", "")   # "DC07"
        cname = re.sub(r"[^a-zA-Z0-9]", "_", finding.contract or "Unknown")
        fname = re.sub(r"[^a-zA-Z0-9]", "_", finding.function or "")
        parts = [bug, cname]
        if fname:
            parts.append(fname)
        parts.append("Harness")
        return "_".join(parts)

    def _output_filename(self, finding: Finding) -> str:
        """
        Generate the output .t.sol filename.
        E.g. 'DC07_DC07_SweeperDelegate_execute_Harness.t.sol'
        """
        return self._test_contract_name(finding) + ".t.sol"