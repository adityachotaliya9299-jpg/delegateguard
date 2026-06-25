// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC03_SafeChainDelegate (FIXED)
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 * @notice Fixed batch executor with chain-bound domain separator - DC-03
 *
 * FIXES APPLIED:
 *   1. Domain separator includes block.chainid - signature is only valid
 *      on the chain it was produced for.
 *   2. Domain separator is recomputed on every call (or cached with chainid
 *      check) so it stays valid across chain forks.
 *   3. Uses OpenZeppelin ECDSA pattern for safe signature recovery.
 */
contract DC03_SafeChainDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc03.safe")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        uint256 nonce;
        bool    initialized;
        // Cache chainid at init time to detect forks
        uint256 cachedChainId;
        bytes32 cachedDomainSeparator;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    // Domain typehash NOW includes chainId field
    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    bytes32 public constant BATCH_TYPEHASH = keccak256(
        "BatchExecute(address[] targets,bytes[] calldatas,uint256[] values,uint256 nonce)"
    );

    //  Domain separator includes block.chainid - chain-specific
    function domainSeparator() public view returns (bytes32) {
        Storage storage s = _store();
        // Recompute if chain changed (e.g., after a fork)
        if (block.chainid == s.cachedChainId) {
            return s.cachedDomainSeparator;
        }
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("DelegateExecutor"),
            keccak256("1"),
            block.chainid,   //  Chain-bound - different on every chain
            address(this)
        ));
    }

    function initialize(address _owner) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized = true;
        s.owner = _owner;
        // Cache domain separator at init time
        s.cachedChainId = block.chainid;
        s.cachedDomainSeparator = _buildDomainSeparator();
    }

    /**
     * @notice Execute a signed batch of calls - chain-locked signature.
     * @dev FIXED: domain separator binds signature to this specific chain.
     *      A mainnet signature cannot be replayed on Arbitrum, Base, etc.
     */
    function executeBatch(
        address[] calldata targets,
        bytes[]   calldata calldatas,
        uint256[] calldata values,
        bytes calldata signature
    ) external {
        Storage storage s = _store();
        uint256 currentNonce = s.nonce;

        bytes32 structHash = keccak256(abi.encode(
            BATCH_TYPEHASH,
            keccak256(abi.encodePacked(targets)),
            keccak256(abi.encodePacked(calldatas)),
            keccak256(abi.encodePacked(values)),
            currentNonce
        ));

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(), // chain-specific domain separator
            structHash
        ));

        address signer = _recoverSafe(digest, signature);
        require(signer == s.owner, "invalid signature");
        require(signer != address(0), "zero address signer");

        s.nonce = currentNonce + 1;

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

    function getChainId() external view returns (uint256) {
        return block.chainid;
    }

    //  Safe ecrecover: validates v and normalizes output
    function _recoverSafe(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s_val; uint8 v;
        assembly {
            r     := calldataload(sig.offset)
            s_val := calldataload(add(sig.offset, 32))
            v     := byte(0, calldataload(add(sig.offset, 64)))
        }
        require(v == 27 || v == 28, "invalid v value");
        // Enforce lower-s to prevent malleability (also fixes DC-08)
        require(
            uint256(s_val) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid s value"
        );
        address recovered = ecrecover(digest, v, r, s_val);
        require(recovered != address(0), "ecrecover failed");
        return recovered;
    }

    receive() external payable {}
}
