// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC06_SafeBatchDelegate (FIXED)
 * @notice Fixed batch executor with global nonce and deadline - DC-06
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIXES APPLIED:
 *   1. Single global nonce (not per-target) — each signature can only be
 *      used once regardless of which target it calls.
 *   2. Deadline field in the signed struct — signatures expire, preventing
 *      indefinite storage and replay at attacker-chosen timing.
 *   3. Nonce is monotonically incremented globally after every execution.
 */
contract DC06_SafeBatchDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc06.safe")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
        uint256 globalNonce; //  Single global nonce
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );

    //  Global nonce + deadline in the signed struct
    bytes32 public constant CALL_TYPEHASH = keccak256(
        "SignedCall(address target,bytes calldata,uint256 value,uint256 nonce,uint256 deadline)"
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
     * @notice Execute a signed call with global nonce and deadline.
     * @dev FIXED: global nonce means each signature is single-use across
     *      all targets. Deadline ensures signatures expire.
     */
    function executeSignedCall(
        address target,
        bytes calldata data,
        uint256 value,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        Storage storage s = _store();

        //  Check deadline before anything else
        require(block.timestamp <= deadline, "DC06: signature expired");

        //  Global nonce check — not per-target
        require(nonce == s.globalNonce, "DC06: invalid nonce");

        bytes32 structHash = keccak256(abi.encode(
            CALL_TYPEHASH,
            target,
            keccak256(data),
            value,
            nonce,
            deadline  //  deadline is part of the signed data
        ));

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(),
            structHash
        ));

        address signer = _recoverSafe(digest, signature);
        require(signer == s.owner, "DC06: invalid signature");
        require(signer != address(0), "DC06: zero signer");

        // Increment global nonce — this signature can never be used again
        s.globalNonce++;

        (bool ok,) = target.call{value: value}(data);
        require(ok, "DC06: call failed");
    }

    function getGlobalNonce() external view returns (uint256) {
        return _store().globalNonce;
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function _recoverSafe(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 sv; uint8 v;
        assembly {
            r  := calldataload(sig.offset)
            sv := calldataload(add(sig.offset, 32))
            v  := byte(0, calldataload(add(sig.offset, 64)))
        }
        require(v == 27 || v == 28, "invalid v");
        require(
            uint256(sv) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0,
            "invalid s"
        );
        return ecrecover(digest, v, r, sv);
    }

    receive() external payable {}
}
