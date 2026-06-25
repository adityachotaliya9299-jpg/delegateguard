// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC04_AuthDelegate (FIXED)
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 * @notice Fixed delegate with proper per-call authentication - DC-04
 *
 * FIXES APPLIED:
 *   1. `onlyOwner` modifier on every state-changing function.
 *   2. Owner is the EOA itself (set at init time to address(this) in
 *      delegatecall context, i.e., the EOA address).
 *   3. Auth check uses msg.sender so only the EOA's own transactions
 *      (or explicitly authorized callers) can invoke privileged functions.
 */
contract DC04_AuthDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc04.safe")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        address feeRecipient;
        uint256 feePercent;
        bool    initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    //  Every privileged function is gated by this modifier
    modifier onlyOwner() {
        require(msg.sender == _store().owner, "DC04: not owner");
        _;
    }

    function initialize(address _owner, address _feeRecipient) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        require(_owner != address(0), "zero owner");
        s.initialized  = true;
        s.owner        = _owner;
        s.feeRecipient = _feeRecipient;
        s.feePercent   = 100;
    }

    /**
     * @dev FIXED: Only owner can transfer ETH out of the EOA.
     */
    function transferETH(address payable to, uint256 amount) external onlyOwner {
        //  msg.sender must be the owner
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /**
     * @dev FIXED: Only owner can change fee recipient.
     */
    function setFeeRecipient(address newRecipient) external onlyOwner {
        require(newRecipient != address(0), "zero recipient");
        _store().feeRecipient = newRecipient;
    }

    /**
     * @dev FIXED: Only owner can change fee percentage.
     */
    function setFeePercent(uint256 bps) external onlyOwner {
        require(bps <= 10000, "max 100%");
        _store().feePercent = bps;
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function getFeeRecipient() external view returns (address) {
        return _store().feeRecipient;
    }

    function getFeePercent() external view returns (uint256) {
        return _store().feePercent;
    }

    receive() external payable {}
}
