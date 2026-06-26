// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC08_MalleableDelegate (VULNERABLE)
 * @notice Demonstrates DC-08: Signature malleability in ecrecover-based flows
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: Uses raw ecrecover() without enforcing the lower-half s constraint.
 * Every valid ECDSA signature (v, r, s) has a mathematically equivalent
 * form (v', r, n-s) where n is the secp256k1 curve order.
 * Both forms recover to the same signer address.
 *
 * If the contract uses the raw signature bytes as a key (e.g., to track
 * "has this signature been used"), an attacker can replay with the
 * alternate form and bypass the used-signature check.
 *
 * Impact: replay of a "spent" authorization, double-spending of a
 * signed permit, or bypassing a signature-based one-time guard.
 */
contract DC08_MalleableDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc08.vulnerable")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
        //  Tracks used signatures by raw bytes — malleable alternate form bypasses this
        mapping(bytes32 => bool) usedSignatures;
        uint256 totalWithdrawn;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address to,uint256 amount)"
    );

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256("WithdrawDelegate"),
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
     * @notice Withdraw ETH with a signed authorization.
     * @dev VULNERABLE: uses raw sig bytes as the "used" key.
     *      The malleable form of the same signature has different bytes
     *      but recovers the same signer — bypassing the usedSignatures check.
     *
     *      Also: ecrecover with high-s values is not rejected.
     */
    function withdraw(
        address payable to,
        uint256 amount,
        bytes calldata signature
    ) external {
        Storage storage s = _store();

        //  Uniqueness check uses raw sig bytes as key
        bytes32 sigHash = keccak256(signature);
        require(!s.usedSignatures[sigHash], "signature already used");

        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        //  Raw ecrecover — accepts both low-s and high-s signatures
        address signer = _recoverRaw(digest, signature);
        require(signer == s.owner, "invalid signature");

        // Mark this signature form as used
        s.usedSignatures[sigHash] = true;
        s.totalWithdrawn += amount;

        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function isSignatureUsed(bytes calldata sig) external view returns (bool) {
        return _store().usedSignatures[keccak256(sig)];
    }

    function getTotalWithdrawn() external view returns (uint256) {
        return _store().totalWithdrawn;
    }

    //  Raw ecrecover: no s-value normalization
    function _recoverRaw(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        //  No check: s <= secp256k1_n/2
        return ecrecover(digest, v, r, s);
    }

    receive() external payable {}
}
