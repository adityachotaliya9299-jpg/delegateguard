"""
DelegateGuard Harness Generator — Tests

Run: pytest harness/tests/ -v
"""
from __future__ import annotations
import sys
from pathlib import Path
import tempfile
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analyzer.core.finding import Finding, BugClass, Severity
from harness.generator import HarnessGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(bug_class: BugClass, contract="VulnDelegate",
                  function="execute", source_file="contracts/VulnDelegate.sol",
                  line=42) -> Finding:
    return Finding(
        bug_class=bug_class,
        severity=Severity.CRITICAL,
        title="Test finding",
        description="Test description",
        contract=contract,
        function=function,
        source_file=source_file,
        line=line,
        recommendation="Test recommendation",
        poc_ref="lab/test/test.t.sol",
    )


# ---------------------------------------------------------------------------
# HarnessGenerator.render()
# ---------------------------------------------------------------------------

class TestHarnessGenerator:

    def setup_method(self):
        self.gen = HarnessGenerator()

    def test_render_dc07_sweeper(self):
        finding = _make_finding(BugClass.DC07_SWEEPER, function="sweepETH")
        result = self.gen.render(finding)

        assert "pragma solidity" in result
        assert "import" in result
        assert "Test" in result
        assert "VulnDelegate" in result
        assert "DC07" in result

    def test_render_dc01_storage_collision(self):
        result = self.gen.render(_make_finding(BugClass.DC01_STORAGE_COLLISION))
        assert "DC-01" in result
        assert "VulnDelegate" in result
        assert "vm.load" in result

    def test_render_dc02_init_frontrun(self):
        result = self.gen.render(_make_finding(BugClass.DC02_INIT_FRONTRUN, function="initialize"))
        assert "DC-02" in result
        assert "FrontRun" in result or "front" in result.lower()

    def test_render_dc03_cross_chain(self):
        result = self.gen.render(_make_finding(BugClass.DC03_CROSS_CHAIN_REPLAY))
        assert "DC-03" in result
        assert "chainId" in result or "chain" in result.lower()

    def test_render_dc04_missing_auth(self):
        result = self.gen.render(_make_finding(BugClass.DC04_MISSING_AUTH, function="transferETH"))
        assert "DC-04" in result
        assert "transferETH" in result

    def test_render_dc05_inner_delegatecall(self):
        result = self.gen.render(_make_finding(BugClass.DC05_INNER_DELEGATECALL, function="executePlugin"))
        assert "DC-05" in result
        assert "Malicious" in result or "plugin" in result.lower()

    def test_render_dc06_batch_replay(self):
        result = self.gen.render(_make_finding(BugClass.DC06_BATCH_REPLAY, function="executeSignedCall"))
        assert "DC-06" in result
        assert "replay" in result.lower() or "nonce" in result.lower()

    def test_render_dc08_sig_malleability(self):
        result = self.gen.render(_make_finding(BugClass.DC08_SIG_MALLEABILITY))
        assert "DC-08" in result
        assert "SECP256K1" in result or "malleable" in result.lower()

    def test_render_pa01_tx_origin(self):
        result = self.gen.render(_make_finding(BugClass.PA01_TX_ORIGIN, function="withdrawAll"))
        assert "PA-01" in result
        assert "tx.origin" in result.lower() or "phishing" in result.lower()

    def test_render_pa02_sender_origin(self):
        result = self.gen.render(_make_finding(BugClass.PA02_SENDER_ORIGIN_GATE, function="claimAirdrop"))
        assert "PA-02" in result

    def test_render_pa03_extcodesize(self):
        result = self.gen.render(_make_finding(BugClass.PA03_EXTCODESIZE, function="deposit"))
        assert "PA-03" in result
        assert "extcodesize" in result.lower() or "etch" in result.lower()

    def test_render_pa04_eoa_reentrancy(self):
        result = self.gen.render(_make_finding(BugClass.PA04_EOA_REENTRANCY, function="withdraw"))
        assert "PA-04" in result
        assert "Reentrant" in result or "reenter" in result.lower()

    def test_render_pa05_eoa_uniqueness(self):
        result = self.gen.render(_make_finding(BugClass.PA05_EOA_UNIQUENESS, function="claimAirdrop"))
        assert "PA-05" in result
        assert "farm" in result.lower() or "sybil" in result.lower()

    def test_all_bug_classes_have_templates(self):
        """Every BugClass must have a template — none should raise."""
        for bug_class in BugClass:
            finding = _make_finding(bug_class)
            try:
                result = self.gen.render(finding)
                assert len(result) > 100, f"Template for {bug_class} is suspiciously short"
            except (ValueError, FileNotFoundError) as e:
                pytest.fail(f"No template for {bug_class}: {e}")

    def test_test_contract_name_is_valid_identifier(self):
        """Generated contract names must be valid Solidity identifiers."""
        import re
        finding = _make_finding(BugClass.DC07_SWEEPER, contract="My.Contract", function="do/something")
        result = self.gen.render(finding)
        # Extract the contract name from the rendered output
        match = re.search(r"contract (\w+) is Test", result)
        assert match, "No 'contract X is Test' found in rendered output"
        name = match.group(1)
        assert re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name), f"Invalid identifier: {name}"

    def test_no_unresolved_placeholders(self):
        """No {placeholder} should remain in rendered output."""
        import re
        for bug_class in BugClass:
            finding = _make_finding(bug_class)
            result = self.gen.render(finding)
            # Find any remaining {word} placeholders (not Solidity {} blocks)
            remaining = re.findall(r"\{[a-z_]+\}", result)
            assert not remaining, \
                f"Unresolved placeholders in {bug_class} template: {remaining}"

    def test_rendered_output_starts_with_license(self):
        finding = _make_finding(BugClass.DC07_SWEEPER)
        result = self.gen.render(finding)
        assert result.strip().startswith("// SPDX-License-Identifier:")

    def test_write_creates_file(self):
        finding = _make_finding(BugClass.DC07_SWEEPER)
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = self.gen.write(finding, output_dir=tmpdir)
            assert out_path.exists()
            assert out_path.suffix == ".sol"
            content = out_path.read_text()
            assert "pragma solidity" in content

    def test_write_creates_output_dir_if_missing(self):
        finding = _make_finding(BugClass.PA04_EOA_REENTRANCY)
        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = Path(tmpdir) / "nested" / "output"
            out_path = self.gen.write(finding, output_dir=str(new_dir))
            assert out_path.exists()

    def test_multiple_findings_get_unique_filenames(self):
        """Two findings with different functions get different filenames."""
        f1 = _make_finding(BugClass.DC07_SWEEPER, function="execute")
        f2 = _make_finding(BugClass.DC07_SWEEPER, function="sweepETH")
        name1 = self.gen._output_filename(f1)
        name2 = self.gen._output_filename(f2)
        assert name1 != name2

    def test_source_file_and_line_in_output(self):
        finding = _make_finding(BugClass.DC07_SWEEPER,
                                source_file="src/delegates/Sweeper.sol", line=99)
        result = self.gen.render(finding)
        assert "Sweeper.sol" in result
        assert "99" in result