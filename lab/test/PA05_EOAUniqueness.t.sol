// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/PA04_PA05_Vulnerable.sol";
import "../src/fixed/PA04_PA05_Fixed.sol";

contract PA05_EOAUniquenessTest is Test {
    PA05_EOAUniqueness public vulnAirdrop;
    PA05_MerkleAirdrop public safeAirdrop;

    address[] public attackerEOAs;

    function setUp() public {
        vulnAirdrop = new PA05_EOAUniqueness();

        // Build Merkle root for 3 allowed addresses
        address alice = makeAddr("alice");
        address bob   = makeAddr("bob");
        address carol = makeAddr("carol");

        // Simple 3-leaf Merkle tree
        bytes32 leafA = keccak256(abi.encodePacked(alice));
        bytes32 leafB = keccak256(abi.encodePacked(bob));
        bytes32 leafC = keccak256(abi.encodePacked(carol));
        bytes32 nodeAB = leafA < leafB
            ? keccak256(abi.encodePacked(leafA, leafB))
            : keccak256(abi.encodePacked(leafB, leafA));
        bytes32 root = nodeAB < leafC
            ? keccak256(abi.encodePacked(nodeAB, leafC))
            : keccak256(abi.encodePacked(leafC, nodeAB));

        safeAirdrop = new PA05_MerkleAirdrop(root);

        // Generate 5 "attacker" EOA addresses (simulates EOA farm)
        for (uint256 i = 0; i < 5; i++) {
            attackerEOAs.push(vm.addr(uint256(keccak256(abi.encode("attacker", i)))));
        }
    }

    /**
     * @notice RED: Attacker farms airdrop with multiple EOAs
     *
     * Each EOA satisfies msg.sender==tx.origin (they send their own txs).
     * The attacker controls N private keys and claims N times.
     */
    function test_RED_EOAFarmDrainsAirdrop() public {
        console.log("=== PA-05 EOA FARM SYBIL ATTACK ===");
        console.log("Attacker EOA farm size:", attackerEOAs.length);

        uint256 claimCount = 0;
        for (uint256 i = 0; i < attackerEOAs.length; i++) {
            address eoaI = attackerEOAs[i];
            // Each EOA calls claimAirdrop with itself as tx.origin
            vm.startPrank(eoaI, eoaI);
            vulnAirdrop.claimAirdrop();
            vm.stopPrank();
            claimCount++;
            assertTrue(vulnAirdrop.hasClaimed(eoaI), "EOA farm address claimed");
        }

        console.log("Attacker claimed", claimCount, "times with EOA farm");
        console.log("All claims succeeded - Sybil attack worked!");
        assertEq(claimCount, attackerEOAs.length, "All farm EOAs claimed successfully");
    }

    /**
     * @notice RED: EOA farm registers multiple governance votes
     */
    function test_RED_EOAFarmInflatesVoterCount() public {
        console.log("=== PA-05 GOVERNANCE SYBIL VIA EOA FARM ===");

        for (uint256 i = 0; i < attackerEOAs.length; i++) {
            vm.startPrank(attackerEOAs[i], attackerEOAs[i]);
            vulnAirdrop.registerVoter();
            vm.stopPrank();
        }

        assertEq(vulnAirdrop.totalVoters(), attackerEOAs.length, "Attacker controls all votes");
        console.log("Attacker registered", vulnAirdrop.totalVoters(), "fake voters");
    }

    /**
     * @notice GREEN: Merkle allowlist blocks EOA farm
     */
    function test_GREEN_MerkleAllowlistBlocksEOAFarm() public {
        console.log("=== PA-05 FIXED: Merkle Allowlist Blocks Farm ===");

        bytes32[] memory emptyProof = new bytes32[](0);

        uint256 blockedCount = 0;
        for (uint256 i = 0; i < attackerEOAs.length; i++) {
            vm.prank(attackerEOAs[i]);
            try safeAirdrop.claimAirdrop(emptyProof) {
                // Should not succeed
            } catch {
                blockedCount++;
            }
        }

        assertEq(blockedCount, attackerEOAs.length, "All farm EOAs blocked by Merkle allowlist");
        console.log("All", blockedCount, "farm EOAs blocked - Sybil attack defeated");
    }
}
