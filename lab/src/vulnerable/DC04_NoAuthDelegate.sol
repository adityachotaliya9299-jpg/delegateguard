// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC04_NoAuthDelegate (VULNERABLE)
 * @notice Demonstrates DC-04: Missing per-call authentication
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: Developer assumed the delegate is only reachable "from the EOA itself"
 * because "only the EOA controls its private key." This mental model is wrong:
 * any external account can CALL the EOA address, which triggers the delegate.
 *
 * The delegate has privileged functions (transferETH, setConfig) with NO
 * msg.sender check. Any caller can invoke them freely.
 *
 * This differs from DC-07 (sweeper) in motivation: the sweeper is deliberately
 * malicious. This bug comes from a developer misunderstanding EIP-7702 call flow.
 */
contract DC04_NoAuthDelegate {
    bytes32 private constant _STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("delegateguard.dc04.vulnerable")) - 1)) & ~bytes32(uint256(0xff));

    struct Storage {
        address owner;
        address feeRecipient;
        uint256 feePercent;   // basis points, e.g. 100 = 1%
        bool    initialized;
    }

    function _store() private pure returns (Storage storage s) {
        bytes32 slot = _STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function initialize(address _owner, address _feeRecipient) external {
        Storage storage s = _store();
        require(!s.initialized, "already initialized");
        s.initialized  = true;
        s.owner        = _owner;
        s.feeRecipient = _feeRecipient;
        s.feePercent   = 100; // 1% default
    }

    /**
     * @dev VULNERABLE: No msg.sender check.
     *      Developer thought "only the EOA can trigger this" - WRONG.
     *      Any external caller triggers the DELEGATECALL into this function.
     */
    function transferETH(address payable to, uint256 amount) external {
        // ❌ Missing: require(msg.sender == _store().owner, "not owner");
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    /**
     * @dev VULNERABLE: Attacker can redirect fees to themselves.
     */
    function setFeeRecipient(address newRecipient) external {
        // ❌ Missing auth check
        _store().feeRecipient = newRecipient;
    }

    /**
     * @dev VULNERABLE: Attacker can change the fee percentage.
     */
    function setFeePercent(uint256 bps) external {
        // ❌ Missing auth check
        require(bps <= 10000, "max 100%");
        _store().feePercent = bps;
    }

    function getFeeRecipient() external view returns (address) {
        return _store().feeRecipient;
    }

    function getFeePercent() external view returns (uint256) {
        return _store().feePercent;
    }

    receive() external payable {}
}
