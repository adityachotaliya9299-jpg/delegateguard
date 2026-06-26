// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC06_BatchReplayDelegate 
 * @author Aditya chotaliya (adityachotaliya.xyz)
 * @notice Demonstrates DC-06: Batch executor replay / nonce gaps
 *
 * BUG: This batch executor uses per-target nonces instead of a single global
 * nonce. An attacker can replay a signed batch by calling it against a
 * different target whose nonce hasn't been used yet, OR exploit nonce gaps
 * when targets are skipped.
 *
 * Secondary bug: no deadline on signed batches - a signature is valid forever,
 * so an attacker can wait for optimal conditions before replaying.
 */
contract DC06_BatchReplayDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc06.vulnerable")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
        //  Per-target nonces instead of a global nonce
        mapping(address => uint256) nonces;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );

    //  Nonce is per-target, not global — allows replay against fresh targets
    //  No deadline field — signatures are valid forever
    bytes32 public constant CALL_TYPEHASH = keccak256(
        "SignedCall(address target,bytes calldata,uint256 value,uint256 nonce)"
    );

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("BatchDelegate"),
            block.chainid,
            address(this)
        ));
    }

    function initialize(address _owner) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized = true;
        s.owner = _owner;
    }

    /**
     * @notice Execute a signed single call.
     * @dev VULNERABLE: nonce is per-target. If victim signs a call to TokenA
     *      with nonce=0, the SAME signature can be replayed against TokenB
     *      (which also has nonce=0 for this EOA).
     *      Also: no deadline means the signature is valid forever.
     */
    function executeSignedCall(
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce,
        bytes calldata signature
    ) external {
        Storage storage s = _store();

        //  Nonce checked per-target, not globally
        require(nonce == s.nonces[target], "invalid nonce");

        bytes32 structHash = keccak256(abi.encode(
            CALL_TYPEHASH,
            target,
            keccak256(data),
            value,
            nonce
        ));

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(),
            structHash
        ));

        address signer = _recover(digest, signature);
        require(signer == s.owner, "invalid signature");

        //  Only increment nonce for THIS target
        s.nonces[target]++;

        (bool ok,) = target.call{value: value}(data);
        require(ok, "call failed");
    }

    function getNonce(address target) external view returns (uint256) {
        return _store().nonces[target];
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 sv; uint8 v;
        assembly {
            r  := calldataload(sig.offset)
            sv := calldataload(add(sig.offset, 32))
            v  := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, sv);
    }

    receive() external payable {}
}
