// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC01_DelegateB (VULNERABLE)
 * @notice Second delegate the EOA switches to — also uses raw unnamespaced storage.
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: Uses slot 0 for `guardian` and slot 1 for `recoveryDelay`.
 * These COLLIDE with DelegateA's `owner` (slot 0) and `dailyLimit` (slot 1).
 *
 * After re-delegation:
 *   - DelegateB reads slot 0 → sees the raw bytes of DelegateA's `owner` address
 *     interpreted as DelegateB's `guardian` address → WRONG
 *   - DelegateB reads slot 1 → sees DelegateA's `dailyLimit` uint256 value
 *     interpreted as `recoveryDelay` → WRONG / potentially zero / exploitable
 */
contract DC01_DelegateB_Vulnerable {
    //  Raw storage slots - SAME slot 0 and slot 1 as DelegateA
    address public guardian;       // slot 0  <- collides with DelegateA.owner
    uint256 public recoveryDelay;  // slot 1  <- collides with DelegateA.dailyLimit

    function initialize(address _guardian, uint256 _delay) external {
        require(guardian == address(0), "already init");
        guardian = _guardian;          // writes to slot 0 -> overwrites DelegateA.owner
        recoveryDelay = _delay;        // writes to slot 1 -> overwrites DelegateA.dailyLimit
    }

    function initiateRecovery() external {
        // BUG: if recoveryDelay was corrupted (e.g., set to 0 by collision),
        // recovery can be instant — bypassing the time-lock entirely
        require(guardian != address(0), "no guardian");
        // ... recovery logic (simplified)
    }

    function getGuardian() external view returns (address) {
        return guardian;        // reads slot 0
    }

    function getRecoveryDelay() external view returns (uint256) {
        return recoveryDelay;   // reads slot 1
    }
}
