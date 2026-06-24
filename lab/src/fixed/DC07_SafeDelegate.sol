// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC07_SafeDelegate (FIXED)
 * @notice Fixed version of the Sweeper delegate — DC-07
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIXES APPLIED:
 *   1. `onlyOwner` modifier — only the delegating EOA itself can call execute.
 *      In EIP-7702 context, the EOA is address(this), so owner = address(this).
 *   2. Call-target allowlist — only pre-approved addresses can be called.
 *   3. No sweepETH helper — arbitrary drain function removed entirely.
 *
 * The key insight: the EOA should only be able to do what its *owner* (itself)
 * explicitly authorized, not what any random external caller requests.
 */
contract DC07_SafeDelegate {
    //  Namespaced storage (ERC-7201) to avoid collision on re-delegation
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc07.storage")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        mapping(address => bool) allowedTargets;
        bool initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    // Only the EOA itself (address(this) in delegatecall context) can call execute
    modifier onlyOwner() {
        // In EIP-7702 delegatecall: address(this) == the EOA, msg.sender == external caller
        // The EOA can only authorize calls via its OWN transaction (msg.sender == address(this)
        // is impossible in practice; real auth requires a signed message checked below).
        // For simplicity here: we require msg.sender == tx.origin (the EOA's own tx)
        // AND tx.origin == address(this) (this call originates from the EOA itself).
        require(
            msg.sender == tx.origin && tx.origin == address(this),
            "DC07: only the EOA owner can call this"
        );
        _;
    }

    /**
     * @notice Initialize the safe delegate with an initial target allowlist.
     * @dev Can only be called once; must be called by the EOA in the same tx
     *      as the EIP-7702 authorization (or in the same bundle).
     */
    function initialize(address[] calldata targets) external {
        Storage storage s = _store();
        require(!s.initialized, "DC07: already initialized");
        require(msg.sender == tx.origin, "DC07: only EOA can initialize");
        s.initialized = true;
        for (uint256 i = 0; i < targets.length; i++) {
            s.allowedTargets[targets[i]] = true;
        }
    }

    /**
     * @notice Add an address to the call-target allowlist.
     */
    function addTarget(address target) external onlyOwner {
        _store().allowedTargets[target] = true;
    }

    /**
     * @notice Remove an address from the allowlist.
     */
    function removeTarget(address target) external onlyOwner {
        _store().allowedTargets[target] = false;
    }

    /**
     * @notice Execute a call — only to allowlisted targets, only by owner.
     */
    function execute(address target, bytes calldata data)
        external
        payable
        onlyOwner
        returns (bool success, bytes memory returnData)
    {
        //  Target must be explicitly allowlisted
        require(_store().allowedTargets[target], "DC07: target not allowed");
        (success, returnData) = target.call{value: msg.value}(data);
        require(success, "DC07: call failed");
    }

    receive() external payable {}
}
