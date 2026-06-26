// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC03_CrossChainDelegate (VULNERABLE)
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 * @notice Demonstrates DC-03: Cross-chain replay via chain_id = 0
 *
 * BUG: This batch executor delegate uses a domain separator that does NOT
 * bind to block.chainid. A signature produced on Ethereum mainnet is valid
 * on every other EVM chain (Arbitrum, Base, Optimism, etc.).
 *
 * The EIP-7702 authorization itself can also be signed with chain_id = 0,
 * making the delegation itself replayable. This contract compounds the problem
 * by also having no chain binding in its own signature verification.
 *
 * Attack flow:
 *   1. Victim signs a batch tx on mainnet (e.g., approve + swap)
 *   2. Attacker replays the SAME signature on Arbitrum where victim also has funds
 *   3. The approve+swap executes on Arbitrum, draining victim's Arbitrum assets
 */
contract DC03_CrossChainDelegate {
    // ERC-7201 storage (good practice, but the replay bug is independent)
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc03.vulnerable")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        uint256 nonce;
        bool    initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    // VULNERABLE domain separator - missing chain_id binding
    // Uses address(this) and a fixed string, but NOT block.chainid
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,address verifyingContract)"
    );

    bytes32 public constant BATCH_TYPEHASH = keccak256(
        "BatchExecute(address[] targets,bytes[] calldatas,uint256[] values,uint256 nonce)"
    );

    function domainSeparator() public view returns (bytes32) {
        //  No block.chainid here - valid on ALL chains
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("DelegateExecutor"),
            keccak256("1"),
            address(this)   // ← this is the EOA address (same on all chains)
        ));
    }

    function initialize(address _owner) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized = true;
        s.owner = _owner;
    }

    /**
     * @notice Execute a signed batch of calls.
     * @dev VULNERABLE: signature is valid on every EVM chain because
     *      the domain separator doesn't include block.chainid.
     */
    function executeBatch(
        address[] calldata targets,
        bytes[]   calldata calldatas,
        uint256[] calldata values,
        bytes calldata signature
    ) external {
        Storage storage s = _store();
        uint256 currentNonce = s.nonce;

        // Build the digest
        bytes32 structHash = keccak256(abi.encode(
            BATCH_TYPEHASH,
            keccak256(abi.encodePacked(targets)),
            keccak256(abi.encode(calldatas)),
            keccak256(abi.encodePacked(values)),
            currentNonce
        ));

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(), //  chain-agnostic domain separator
            structHash
        ));

        // Recover signer
        address signer = _recover(digest, signature);
        require(signer == s.owner, "invalid signature");

        // Increment nonce
        s.nonce = currentNonce + 1;

        // Execute all calls
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call{value: values[i]}(calldatas[i]);
            require(ok, "call failed");
        }
    }

    function getNonce() external view returns (uint256) {
        return _store().nonce;
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s_val; uint8 v;
        assembly {
            r     := calldataload(sig.offset)
            s_val := calldataload(add(sig.offset, 32))
            v     := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s_val);
    }

    receive() external payable {}
}
