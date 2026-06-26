// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC08_SafeDelegate (FIXED)
 * @notice Fixed delegate immune to signature malleability - DC-08
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIXES APPLIED:
 *   1. Lower-s enforcement: reject any signature where s > secp256k1_n/2.
 *      This eliminates the malleable alternate form entirely.
 *   2. Replace sig-bytes-as-key with a monotonic nonce — nonces are
 *      unforgeable and immune to the malleability trick entirely.
 *   3. Validate v is exactly 27 or 28.
 */
contract DC08_SafeDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc08.safe")) - 1)) & ~bytes32(uint256(0xff));

    // secp256k1 curve order n / 2
    uint256 private constant _HALF_CURVE_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    struct Storage {
        address owner;
        bool    initialized;
        uint256 nonce; //  Monotonic nonce replaces sig-bytes-as-key
        uint256 totalWithdrawn;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    bytes32 public constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );
    //  Nonce added to signed struct
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256(
        "Withdraw(address to,uint256 amount,uint256 nonce)"
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
     * @dev FIXED: nonce-based replay protection + lower-s enforcement.
     *      Malleable alternate signature has same (r, |s|, to, amount) but
     *      different nonce requirement — and lower-s is enforced anyway.
     */
    function withdraw(
        address payable to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external {
        Storage storage s = _store();

        //  Monotonic nonce check — immune to malleability
        require(nonce == s.nonce, "DC08: invalid nonce");

        bytes32 structHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, to, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));

        //  Safe recover enforces lower-s and valid v
        address signer = _recoverSafe(digest, signature);
        require(signer == s.owner, "DC08: invalid signature");
        require(signer != address(0), "DC08: zero signer");

        //  Increment nonce after use
        s.nonce++;
        s.totalWithdrawn += amount;

        (bool ok,) = to.call{value: amount}("");
        require(ok, "DC08: transfer failed");
    }

    function getNonce() external view returns (uint256) {
        return _store().nonce;
    }

    function getTotalWithdrawn() external view returns (uint256) {
        return _store().totalWithdrawn;
    }

    //  Safe ecrecover: enforces lower-s and valid v
    function _recoverSafe(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        //  v must be 27 or 28
        require(v == 27 || v == 28, "DC08: invalid v");
        //  s must be in lower half of curve order — eliminates malleable form
        require(uint256(s) <= _HALF_CURVE_ORDER, "DC08: high-s rejected");
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0), "DC08: ecrecover failed");
        return recovered;
    }

    receive() external payable {}
}
