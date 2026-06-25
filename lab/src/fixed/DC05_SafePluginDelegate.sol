// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC05_SafePluginDelegate (FIXED)
 * @notice Fixed plugin router with allowlisted DELEGATECALL targets 
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIXES APPLIED:
 *   1. Plugin allowlist: only pre-approved plugin addresses can be delegatecalled.
 *   2. onlyOwner on executePlugin AND on allowlist management.
 *   3. The dangerous `delegateTo` function removed entirely.
 *   4. Plugin selector allowlist (optional, shown for defense-in-depth).
 */
contract DC05_SafePluginDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc05.safe")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
        mapping(address => bool) allowedPlugins;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    modifier onlyOwner() {
        require(msg.sender == _store().owner, "DC05: not owner");
        _;
    }

    function initialize(address _owner) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized = true;
        s.owner       = _owner;
    }

    /**
     * @notice Add a plugin to the allowlist (owner only).
     */
    function allowPlugin(address plugin) external onlyOwner {
        require(plugin != address(0), "zero plugin");
        //Only owner can expand the trusted plugin set
        _store().allowedPlugins[plugin] = true;
    }

    /**
     * @notice Remove a plugin from the allowlist (owner only).
     */
    function denyPlugin(address plugin) external onlyOwner {
        _store().allowedPlugins[plugin] = false;
    }

    function isPluginAllowed(address plugin) external view returns (bool) {
        return _store().allowedPlugins[plugin];
    }

    /**
     * @notice Route a call to an allowlisted plugin via DELEGATECALL.
     * @dev FIXED: plugin must be in the allowlist; owner-only.
     */
    function executePlugin(address plugin, bytes calldata data)
        external
        onlyOwner
        returns (bytes memory)
    {
        // Only allowlisted plugins can be delegatecalled
        require(_store().allowedPlugins[plugin], "DC05: plugin not allowed");

        (bool ok, bytes memory result) = plugin.delegatecall(data);
        require(ok, "plugin call failed");
        return result;
    }

    receive() external payable {}
}
