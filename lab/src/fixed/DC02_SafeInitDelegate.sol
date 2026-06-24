// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC02_SafeInitDelegate (FIXED)
 * @notice Fixed delegate with front-run-resistant initialization — DC-02
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIXES APPLIED:
 *   1. `initialize()` requires `msg.sender == tx.origin` AND
 *      `tx.origin == address(this)`: only the EOA itself can call initialize,
 *      and only via its own transaction (not a contract intermediary).
 *      This makes front-running impossible — the attacker would need the
 *      victim's private key to send a tx originating from the victim EOA.
 *
 *   2. ERC-7201 namespaced storage (fixes DC-01 simultaneously).
 *
 *   3. `initializer` modifier pattern (inspired by OZ Initializable) with
 *      the additional tx.origin self-check.
 *
 * NOTE: The gold-standard fix is to include initialization calldata in the
 * EIP-7702 authorization bundle itself (one atomic tx), so authorization
 * and initialization happen in the same transaction. This contract enforces
 * the self-auth check as a defense-in-depth measure.
 */
contract DC02_SafeInitDelegate {
    // ERC-7201 namespaced storage
    bytes32 private constant _STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256("delegateguard.dc02.storage")) - 1)
    ) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    //  Initialization guard: only the EOA itself can initialize
    modifier selfAuthInitializer() {
        Storage storage s = _store();
        require(!s.initialized, "DC02: already initialized");
        // In EIP-7702 delegatecall context:
        //   address(this) == the EOA
        //   tx.origin     == whoever sent the transaction
        // For the victim to initialize their own delegate, they must send
        // the tx themselves: tx.origin == address(this).
        require(
            msg.sender == tx.origin && tx.origin == address(this),
            "DC02: only the EOA can initialize itself"
        );
        s.initialized = true;
        _;
    }

    /**
     * @notice Initialize the delegate. Can ONLY be called by the EOA itself
     *         in its own transaction — front-running is impossible.
     */
    function initialize(address _owner) external selfAuthInitializer {
        //  By the time we reach here, we've verified:
        //    - Not yet initialized
        //    - msg.sender == tx.origin (not a contract calling us)
        //    - tx.origin == address(this) (the EOA is calling itself)
        _store().owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == _store().owner, "DC02: not owner");
        _;
    }

    function execute(address target, bytes calldata data)
        external
        payable
        onlyOwner
        returns (bool, bytes memory)
    {
        return target.call{value: msg.value}(data);
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function isInitialized() external view returns (bool) {
        return _store().initialized;
    }

    receive() external payable {}
}
