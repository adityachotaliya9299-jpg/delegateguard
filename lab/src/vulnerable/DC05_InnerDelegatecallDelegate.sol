// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC05_InnerDelegatecallDelegate (VULNERABLE)
 * @notice Demonstrates DC-05: Unsafe inner DELEGATECALL
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: This delegate is itself a "plugin router" - it accepts a target and
 * calldata and issues a DELEGATECALL to that target. Because it runs in the
 * EOA's context (via the 7702 outer delegatecall), the inner delegatecall
 * ALSO runs in the EOA's context with no restrictions on the target.
 *
 * Trust chain:
 *   External caller
 *     -> EOA (has 7702 delegation to this contract)
 *       -> DELEGATECALL -> this contract (runs in EOA context)
 *         -> DELEGATECALL -> attacker's contract (ALSO runs in EOA context)
 *
 * The innermost callee executes arbitrary code in the EOA's storage context
 * with access to all the EOA's assets and storage. No attestation, no allowlist.
 *
 * Real-world analog: proxy contracts that expose a raw delegatecall interface.
 */
contract DC05_InnerDelegatecallDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc05.vulnerable")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        bool    initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function initialize(address _owner) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized = true;
        s.owner       = _owner;
    }

    /**
     * @notice Route a call to a plugin via DELEGATECALL.
     * @dev VULNERABLE: No allowlist on `plugin`. Any address can be passed.
     *      The plugin executes in the EOA's storage context.
     *      An attacker passes their own malicious contract as `plugin`.
     */
    function executePlugin(address plugin, bytes calldata data)
        external
        returns (bytes memory)
    {
        require(msg.sender == _store().owner, "not owner");

        //  Inner DELEGATECALL with unconstrained target
        // If `plugin` is attacker-controlled, they can:
        //   - Read/write any storage slot in the EOA
        //   - Transfer any ETH or tokens the EOA holds
        //   - Self-destruct the EOA (pre-Cancun)
        (bool ok, bytes memory result) = plugin.delegatecall(data);
        require(ok, "plugin call failed");
        return result;
    }

    /**
     * @dev VULNERABLE: A second path - direct delegatecall with no owner check at all.
     */
    function delegateTo(address target, bytes calldata data)
        external
        returns (bytes memory)
    {
        //  No auth check AND no allowlist - double vulnerability
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return result;
    }

    receive() external payable {}
}
