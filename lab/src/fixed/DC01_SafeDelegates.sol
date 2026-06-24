// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC01_DelegateA_Safe (FIXED)
 * @notice Fixed DelegateA using ERC-7201 namespaced storage.
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * FIX: Storage variables live at a deterministic, collision-resistant slot
 * derived from a namespace string unique to this contract.
 *
 * ERC-7201 formula:
 *   slot = keccak256(abi.encode(uint256(keccak256("namespace.string")) - 1)) & ~bytes32(uint256(0xff))
 *
 * This guarantees DelegateA's storage never overlaps with DelegateB's,
 * regardless of how many times the EOA re-delegates.
 */
contract DC01_DelegateA_Safe {
    // ✅ ERC-7201 namespaced storage slot — unique to DelegateA
    bytes32 private constant _STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256("delegateguard.dc01.delegateA")) - 1)
    ) & ~bytes32(uint256(0xff));

    struct DelegateAStorage {
        address owner;
        uint256 dailyLimit;
        bool initialized;
    }

    function _store() private pure returns (DelegateAStorage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    function initialize(address _owner, uint256 _limit) external {
        DelegateAStorage storage s = _store();
        require(!s.initialized, "already init");
        s.initialized = true;
        s.owner = _owner;
        s.dailyLimit = _limit;
    }

    function setDailyLimit(uint256 _limit) external {
        DelegateAStorage storage s = _store();
        require(msg.sender == s.owner, "not owner");
        s.dailyLimit = _limit;
    }

    function getOwner() external view returns (address) {
        return _store().owner;
    }

    function getDailyLimit() external view returns (uint256) {
        return _store().dailyLimit;
    }
}

/**
 * @title DC01_DelegateB_Safe (FIXED)
 * @notice Fixed DelegateB using ERC-7201 namespaced storage.
 *
 * FIX: Different namespace string → completely different storage slot.
 * Even though both delegates use `address` + `uint256` as their first two
 * variables, they never overlap because the base slot is different.
 */
contract DC01_DelegateB_Safe {
    //  ERC-7201 namespaced storage slot — unique to DelegateB (different namespace)
    bytes32 private constant _STORAGE_SLOT = keccak256(
        abi.encode(uint256(keccak256("delegateguard.dc01.delegateB")) - 1)
    ) & ~bytes32(uint256(0xff));

    struct DelegateBStorage {
        address guardian;
        uint256 recoveryDelay;
        bool initialized;
    }

    function _store() private pure returns (DelegateBStorage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    function initialize(address _guardian, uint256 _delay) external {
        DelegateBStorage storage s = _store();
        require(!s.initialized, "already init");
        s.initialized = true;
        s.guardian = _guardian;
        s.recoveryDelay = _delay;
    }

    function initiateRecovery() external {
        DelegateBStorage storage s = _store();
        require(s.guardian != address(0), "no guardian");
        require(s.recoveryDelay > 0, "zero delay — init not complete");
        // ... safe recovery logic
    }

    function getGuardian() external view returns (address) {
        return _store().guardian;
    }

    function getRecoveryDelay() external view returns (uint256) {
        return _store().recoveryDelay;
    }
}
