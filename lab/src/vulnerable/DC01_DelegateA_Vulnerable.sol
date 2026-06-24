// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC01_DelegateA (VULNERABLE)
 * @notice First delegate an EOA points to — uses raw unnamespaced storage.
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: Uses slot 0 for `owner` and slot 1 for `dailyLimit`.
 * When the EOA later switches to DelegateB (which also uses slot 0 and 1
 * for different variables), both delegates corrupt each other's data.
 *
 * This is DC-01: Storage Collision on Re-delegation.
 */
contract DC01_DelegateA_Vulnerable {
    //  Raw storage slots — slot 0 and slot 1
    address public owner;       // slot 0
    uint256 public dailyLimit;  // slot 1

    function initialize(address _owner, uint256 _limit) external {
        require(owner == address(0), "already init");
        owner = _owner;         // writes to slot 0
        dailyLimit = _limit;    // writes to slot 1
    }

    function setDailyLimit(uint256 _limit) external {
        require(msg.sender == owner, "not owner");
        dailyLimit = _limit;
    }

    function getOwner() external view returns (address) {
        return owner;           // reads slot 0
    }

    function getDailyLimit() external view returns (uint256) {
        return dailyLimit;      // reads slot 1
    }
}
