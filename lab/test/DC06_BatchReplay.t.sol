// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC06_BatchReplayDelegate.sol";
import "../src/fixed/DC06_SafeBatchDelegate.sol";

contract DC06_BatchReplayTest is Test {
    address payable public victimEOA;
    uint256 public victimKey;
    address public attacker;
    address payable public tokenA;
    address payable public tokenB;

    DC06_BatchReplayDelegate public vulnDelegate;
    DC06_SafeBatchDelegate   public safeDelegate;

    function setUp() public {
        victimKey = 0xB0B;
        victimEOA = payable(vm.addr(victimKey));
        attacker  = makeAddr("attacker");
        tokenA    = payable(makeAddr("tokenA"));
        tokenB    = payable(makeAddr("tokenB"));

        vm.deal(victimEOA, 10 ether);

        vulnDelegate = new DC06_BatchReplayDelegate();
        safeDelegate = new DC06_SafeBatchDelegate();
    }

    // =========================================================================
    // RED TESTS - per-target nonce replay
    // =========================================================================

    /**
     * @notice RED: Victim signs a call to tokenA; attacker replays against tokenB
     *
     * Both tokenA and tokenB have nonce=0 for this EOA (per-target nonces).
     * The same signature works against tokenB because the nonce matches.
     */
    function test_RED_PerTargetNonceReplay() public {
        console.log("=== DC-06 PER-TARGET NONCE REPLAY ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC06_BatchReplayDelegate(victimEOA).initialize(victimEOA);

        // Victim signs: send 1 ETH to tokenA, nonce=0
        bytes32 digest = _buildVulnDigest(tokenA, "", 1 ether, 0);
        bytes memory sig = _sign(victimKey, digest);

        console.log("Victim signed: send 1 ETH to tokenA with nonce=0");

        // Legitimate execution against tokenA - works as intended
        DC06_BatchReplayDelegate(victimEOA).executeSignedCall(tokenA, "", 1 ether, 0, sig);
        console.log("tokenA nonce after legitimate call:", DC06_BatchReplayDelegate(victimEOA).getNonce(tokenA));
        assertEq(tokenA.balance, 1 ether, "tokenA received ETH");

        // REPLAY: attacker uses the SAME signature against tokenB
        // tokenB nonce is still 0 (independent per-target nonce)
        assertEq(DC06_BatchReplayDelegate(victimEOA).getNonce(tokenB), 0, "tokenB nonce is still 0");

        vm.prank(attacker);
        DC06_BatchReplayDelegate(victimEOA).executeSignedCall(tokenB, "", 1 ether, 0, sig);

        console.log("REPLAY: same sig used against tokenB!");
        console.log("tokenB balance:", tokenB.balance / 1e18, "ETH (should be 0)");
        assertEq(tokenB.balance, 1 ether, "REPLAY: tokenB also drained with same signature");
        assertEq(victimEOA.balance, 8 ether, "Victim lost 2 ETH from one signature");
    }

    /**
     * @notice RED: Expired-looking sig is valid forever (no deadline)
     *
     * Victim signed months ago. Attacker holds the signature and replays
     * it now when conditions are favorable (e.g., victim just received tokens).
     */
    function test_RED_NoDeadlineSignatureValidForever() public {
        console.log("=== DC-06 NO DEADLINE: SIGNATURE VALID FOREVER ===");

        _etch7702(victimEOA, address(vulnDelegate));
        vm.prank(victimEOA);
        DC06_BatchReplayDelegate(victimEOA).initialize(victimEOA);

        // Victim signed this 180 days ago
        bytes32 digest = _buildVulnDigest(attacker, "", 1 ether, 0);
        bytes memory sig = _sign(victimKey, digest);

        // Fast-forward 180 days
        vm.warp(block.timestamp + 180 days);

        // Signature still works - no expiry check
        vm.prank(attacker);
        DC06_BatchReplayDelegate(victimEOA).executeSignedCall(attacker, "", 1 ether, 0, sig);

        assertEq(attacker.balance, 1 ether, "180-day-old signature still valid - no deadline");
        console.log("180-day-old signature replayed successfully");
    }

    // =========================================================================
    // GREEN TESTS - global nonce and deadline block replays
    // =========================================================================

    /**
     * @notice GREEN: Same sig CANNOT be replayed against different target with safe delegate
     */
    function test_GREEN_GlobalNonceBlocksTargetReplay() public {
        console.log("=== DC-06 FIXED: Global Nonce Blocks Replay ===");

        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC06_SafeBatchDelegate(victimEOA).initialize(victimEOA);

        uint256 deadline = block.timestamp + 1 hours;

        // Victim signs for tokenA with global nonce=0
        bytes32 digest = _buildSafeDigest(tokenA, "", 1 ether, 0, deadline);
        bytes memory sig = _sign(victimKey, digest);

        // Legitimate execution against tokenA
        DC06_SafeBatchDelegate(victimEOA).executeSignedCall(tokenA, "", 1 ether, 0, deadline, sig);
        assertEq(tokenA.balance, 1 ether, "tokenA received ETH");
        assertEq(DC06_SafeBatchDelegate(victimEOA).getGlobalNonce(), 1, "Global nonce is now 1");

        // REPLAY against tokenB - fails because global nonce is now 1, not 0
        vm.prank(attacker);
        vm.expectRevert("DC06: invalid nonce");
        DC06_SafeBatchDelegate(victimEOA).executeSignedCall(tokenB, "", 1 ether, 0, deadline, sig);

        assertEq(tokenB.balance, 0, "tokenB untouched - replay blocked");
        console.log("Replay blocked. tokenB balance:", tokenB.balance);
    }

    /**
     * @notice GREEN: Expired signature is rejected
     */
    function test_GREEN_ExpiredSignatureRejected() public {
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC06_SafeBatchDelegate(victimEOA).initialize(victimEOA);

        // Victim signs with 1-hour deadline
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = _buildSafeDigest(attacker, "", 1 ether, 0, deadline);
        bytes memory sig = _sign(victimKey, digest);

        // Fast-forward past deadline
        vm.warp(deadline + 1);

        // Signature rejected - expired
        vm.prank(attacker);
        vm.expectRevert("DC06: signature expired");
        DC06_SafeBatchDelegate(victimEOA).executeSignedCall(attacker, "", 1 ether, 0, deadline, sig);

        assertEq(attacker.balance, 0, "No ETH stolen - signature expired");
        console.log("=== Expired signature correctly rejected ===");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    function _etch7702(address eoa, address delegate) internal {
        vm.etch(eoa, delegate.code);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _buildVulnDigest(address target, bytes memory data, uint256 value, uint256 nonce)
        internal view returns (bytes32)
    {
        bytes32 DOMAIN_TH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
        bytes32 CALL_TH   = keccak256("SignedCall(address target,bytes calldata,uint256 value,uint256 nonce)");
        bytes32 domSep = keccak256(abi.encode(DOMAIN_TH, keccak256("BatchDelegate"), block.chainid, address(victimEOA)));
        bytes32 structHash = keccak256(abi.encode(CALL_TH, target, keccak256(data), value, nonce));
        return keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
    }

    function _buildSafeDigest(address target, bytes memory data, uint256 value, uint256 nonce, uint256 deadline)
        internal view returns (bytes32)
    {
        bytes32 DOMAIN_TH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
        bytes32 CALL_TH   = keccak256("SignedCall(address target,bytes calldata,uint256 value,uint256 nonce,uint256 deadline)");
        bytes32 domSep = keccak256(abi.encode(DOMAIN_TH, keccak256("BatchDelegate"), block.chainid, address(victimEOA)));
        bytes32 structHash = keccak256(abi.encode(CALL_TH, target, keccak256(data), value, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
    }
}
