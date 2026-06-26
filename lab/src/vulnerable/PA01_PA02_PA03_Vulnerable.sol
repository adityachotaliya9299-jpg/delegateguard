// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PA01_TxOriginAuth (VULNERABLE)
 * @notice PA-01: tx.origin used for authentication
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: Uses tx.origin to verify the caller is the "owner".
 * Post-7702, a delegated EOA is still tx.origin for its own transactions,
 * BUT any contract the EOA calls can also be tx.origin in that call chain.
 * More critically: tx.origin auth can be abused via phishing contracts
 * that get the victim to call them, then call this protocol on their behalf.
 */
contract PA01_TxOriginAuth {
    address public owner;
    mapping(address => uint256) public balances;

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * @dev VULNERABLE: tx.origin check instead of msg.sender.
     *      An attacker can deploy a phishing contract, trick the owner into
     *      calling it, and that phishing contract calls withdrawAll() here.
     *      tx.origin == owner passes, but msg.sender == phishing contract.
     */
    function withdrawAll(address payable to) external {
        // ❌ tx.origin can be spoofed via intermediary contract
        require(tx.origin == owner, "not owner");
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

/**
 * @title PA02_SenderOriginGate (VULNERABLE)
 * @notice PA-02: msg.sender == tx.origin used as EOA gate
 *
 * BUG: `msg.sender == tx.origin` was a reliable "is this an EOA?" check
 * pre-7702 because contracts can't be tx.origin. Post-7702, a delegated
 * EOA has code but IS still tx.origin for its own transactions.
 *
 * The check passes for delegated EOAs even though they now have code
 * and can execute complex logic — breaking any invariant built on this.
 */
contract PA02_SenderOriginGate {
    mapping(address => bool) public claimed;
    uint256 public constant AIRDROP_AMOUNT = 100 ether;

    /**
     * @dev VULNERABLE: Allows delegated EOAs to claim airdrop.
     *      Pre-7702 intent was "only pure EOAs, no contracts".
     *      Post-7702 a delegated EOA passes this check but has contract code.
     */
    function claimAirdrop() external {
        //  This check no longer reliably identifies "pure" EOAs
        require(msg.sender == tx.origin, "only EOAs can claim");
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        // In real contract: transfer AIRDROP_AMOUNT to msg.sender
    }

    function hasClaimed(address a) external view returns (bool) {
        return claimed[a];
    }
}

/**
 * @title PA03_ExtcodesizeGate (VULNERABLE)
 * @notice PA-03: extcodesize == 0 used to detect EOAs
 *
 * BUG: `extcodesize(addr) == 0` was the canonical "no code = EOA" check.
 * Post-7702, a delegated EOA has code (the 23-byte delegation designator
 * `0xef0100 || delegate_address`), so extcodesize returns 23.
 * Any reentrancy guard or access control using this check is broken.
 */
contract PA03_ExtcodesizeGate {
    mapping(address => uint256) public deposits;
    bool private _locked;

    /**
     * @dev VULNERABLE: Uses extcodesize to prevent "contracts" from depositing.
     *      Post-7702, a delegated EOA has extcodesize > 0 and is blocked,
     *      OR if the check is inverted (allow only codesize==0), it admits
     *      only undelegated EOAs — breaking UX for all 7702 wallet users.
     */
    function deposit() external payable {
        //  Delegated EOAs fail this check — their extcodesize is 23 (designator length)
        require(_isEOA(msg.sender), "only EOAs can deposit");
        deposits[msg.sender] += msg.value;
    }

    /**
     * @dev VULNERABLE: This reentrancy guard assumes EOAs (codesize==0) can't
     *      reenter. Post-7702 a delegated EOA CAN reenter.
     */
    function withdraw(uint256 amount) external {
        require(!_locked, "reentrant");
        require(deposits[msg.sender] >= amount, "insufficient");

        //  Assumes EOA callers can't reenter, so skips the lock for them
        if (!_isEOA(msg.sender)) {
            _locked = true;
        }

        deposits[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        _locked = false;
    }

    function _isEOA(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size == 0;
    }
}
