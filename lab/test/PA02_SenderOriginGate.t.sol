// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/PA01_PA02_PA03_Vulnerable.sol";
import "../src/fixed/PA01_PA02_PA03_Fixed.sol";

contract PA02_SenderOriginGateTest is Test {
    PA02_SenderOriginGate public vulnAirdrop;
    PA02_AllowlistGate    public safeAirdrop;

    address public delegatedEOA;
    address public plainEOA;

    function setUp() public {
        delegatedEOA = makeAddr("delegatedEOA");
        plainEOA     = makeAddr("plainEOA");

        vulnAirdrop = new PA02_SenderOriginGate();

        // Build a trivial Merkle root for just plainEOA
        bytes32 leaf = keccak256(abi.encodePacked(plainEOA));
        safeAirdrop  = new PA02_AllowlistGate(leaf); // root = single leaf
    }

    /**
     * @notice RED: Delegated EOA passes msg.sender==tx.origin check
     *
     * A delegated EOA is still tx.origin for its own transactions,
     * so msg.sender == tx.origin passes even though the EOA has code.
     */
    function test_RED_DelegatedEOAPassesOriginCheck() public {
        console.log("=== PA-02 MSG.SENDER==TX.ORIGIN CHECK BYPASS ===");

        // Simulate delegated EOA calling directly (it IS tx.origin for its own tx)
        vm.startPrank(delegatedEOA, delegatedEOA);
        vulnAirdrop.claimAirdrop();
        vm.stopPrank();

        assertTrue(vulnAirdrop.hasClaimed(delegatedEOA), "Delegated EOA passed the check");
        console.log("Delegated EOA bypassed EOA-only gate");
    }

    /**
     * @notice GREEN: Allowlist blocks non-listed addresses regardless of EOA status
     */
    function test_GREEN_AllowlistBlocksUnlistedAddress() public {
        console.log("=== PA-02 FIXED: Merkle Allowlist ===");

        bytes32[] memory emptyProof = new bytes32[](0);

        // delegatedEOA is not in the allowlist
        vm.prank(delegatedEOA);
        vm.expectRevert("not in allowlist");
        safeAirdrop.claimAirdrop(emptyProof);

        assertFalse(safeAirdrop.hasClaimed(delegatedEOA), "Not in allowlist - blocked");
        console.log("Unlisted address blocked regardless of EOA/contract status");
    }

    /**
     * @notice GREEN: Listed address can claim with valid proof
     */
    function test_GREEN_ListedAddressCanClaim() public {
        // plainEOA is the only leaf, so root == leaf, proof is empty
        bytes32[] memory emptyProof = new bytes32[](0);

        vm.prank(plainEOA);
        safeAirdrop.claimAirdrop(emptyProof);

        assertTrue(safeAirdrop.hasClaimed(plainEOA), "Listed address claimed successfully");
    }
}
