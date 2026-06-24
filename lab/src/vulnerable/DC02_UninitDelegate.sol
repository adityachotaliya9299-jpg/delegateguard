// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC02_UninitDelegate (VULNERABLE)
 * @notice Demonstrates DC-02: Unprotected / Front-runnable Initializer
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: The `initialize()` function has no atomicity guarantee with the
 * EIP-7702 authorization. A victim signs an authorization to delegate to
 * this contract, broadcasts it, and an attacker's bot sees the pending tx
 * in the mempool. The bot front-runs with a call to `initialize(attacker)`,
 * becoming the owner BEFORE the victim's own initialization goes through.
 *
 * This is especially dangerous because:
 *   1. The victim's authorization tx still succeeds (delegation is set)
 *   2. But the delegate is now owned by the attacker
 *   3. Attacker can drain the EOA at will via the owner-gated execute()
 */
contract DC02_UninitDelegate {
    //  Raw storage — also has DC-01 issue but focus is on the init race
    address public owner;
    bool    public initialized;

    /**
     * @notice VULNERABLE: Anyone can call this before the victim does.
     * @dev No tx.origin check, no signature requirement, no atomicity.
     *      Just a plain "first caller wins" pattern.
     */
    function initialize(address _owner) external {
        //  Only checks initialized flag — doesn't verify the caller is the EOA
        require(!initialized, "already initialized");
        initialized = true;
        owner = _owner;  // ← attacker passes attacker's address here
    }

    function execute(address target, bytes calldata data)
        external
        payable
        returns (bool, bytes memory)
    {
        require(msg.sender == owner, "not owner");
        return target.call{value: msg.value}(data);
    }

    function getOwner() external view returns (address) {
        return owner;
    }

    receive() external payable {}
}
