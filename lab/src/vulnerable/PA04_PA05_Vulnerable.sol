// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PA04_EOAReentrancy (VULNERABLE)
 * @notice PA-04: EOA-only reentrancy paths — the most underappreciated PA bug
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: The developer added reentrancy protection only for contract callers,
 * reasoning "EOAs can't reenter because they have no code to execute on
 * ETH receipt." Post-7702, a delegated EOA's receive() hook (in the delegate)
 * CAN execute code when ETH is sent — enabling reentrancy from an "EOA".
 */
contract PA04_EOAReentrancy {
    mapping(address => uint256) public balances;
    // ❌ Reentrancy guard only applied to contract callers
    mapping(address => bool) private _contractLocked;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @dev VULNERABLE: Skips reentrancy guard for EOA callers.
     *      Post-7702, a delegated EOA has a receive() hook in the delegate
     *      that can call back into this function before the balance is zeroed.
     */
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        bool isContract = _hasCode(msg.sender);

        // ❌ Only protects against contract reentrancy
        if (isContract) {
            require(!_contractLocked[msg.sender], "reentrant");
            _contractLocked[msg.sender] = true;
        }
        // ❌ EOA callers bypass the guard entirely — no lock set

        // Balance zeroed AFTER the call — classic reentrancy setup
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0; // ❌ Too late if reentered

        if (isContract) {
            _contractLocked[msg.sender] = false;
        }
    }

    function _hasCode(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}

/**
 * @title PA05_EOAUniqueness (VULNERABLE)
 * @notice PA-05: Airdrop / access gates equating EOA = unique human
 *
 * BUG: The contract uses EOA status as a Sybil-resistance primitive.
 * Pre-7702: "one EOA = one unique human" was a weak but common assumption.
 * Post-7702: a single operator can control many EOA smart accounts via
 * different delegate contracts, all delegated from programmatically
 * generated keys — making Sybil attacks trivially easy.
 *
 * Additionally: msg.sender == tx.origin check (PA-02) is used here too,
 * compounding the issue.
 */
contract PA05_EOAUniqueness {
    mapping(address => bool) public hasClaimedAirdrop;
    mapping(address => bool) public isRegisteredVoter;
    uint256 public totalVoters;

    uint256 public constant AIRDROP_AMOUNT = 1000e18;

    /**
     * @dev VULNERABLE: Assumes 1 EOA = 1 unique person.
     *      An attacker generates N EOAs, delegates them all programmatically,
     *      and claims N airdrops. The msg.sender==tx.origin check passes
     *      for each delegated EOA (they still satisfy it for their own txs).
     */
    function claimAirdrop() external {
        // ❌ These checks are insufficient post-7702
        require(msg.sender == tx.origin, "no contracts");
        require(!hasClaimedAirdrop[msg.sender], "already claimed");

        hasClaimedAirdrop[msg.sender] = true;
        // Transfer AIRDROP_AMOUNT to msg.sender (simplified)
    }

    /**
     * @dev VULNERABLE: Governance voting that allows Sybil via EOA farms.
     */
    function registerVoter() external {
        require(msg.sender == tx.origin, "no contracts");
        require(!isRegisteredVoter[msg.sender], "already registered");
        isRegisteredVoter[msg.sender] = true;
        totalVoters++;
    }

    function hasClaimed(address a) external view returns (bool) {
        return hasClaimedAirdrop[a];
    }
}
