// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PA01_MsgSenderAuth (FIXED)
 * @notice Fix for PA-01: replace tx.origin with msg.sender
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 */
contract PA01_MsgSenderAuth {
    address public owner;
    mapping(address => uint256) public balances;

    constructor(address _owner) {
        owner = _owner;
    }

    /**
     * @dev FIXED: msg.sender cannot be spoofed by an intermediary contract.
     *      Only the owner address itself can call withdrawAll directly.
     */
    function withdrawAll(address payable to) external {
        //  msg.sender is unforgeable — no phishing contract can spoof this
        require(msg.sender == owner, "not owner");
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "transfer failed");
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

/**
 * @title PA02_NoEOAGate (FIXED)
 * @notice Fix for PA-02: remove unreliable EOA gate, use allowlist or KYC
 *
 * The correct fix depends on what the gate was protecting:
 *   - Airdrop Sybil resistance: use Merkle proof allowlist or ZK proof of personhood
 *   - Reentrancy: use a proper reentrancy guard (see PA03 fix)
 *   - Bot protection: use commit-reveal or time-locks
 *
 * Here we show the Merkle allowlist pattern as the gold standard.
 */
contract PA02_AllowlistGate {
    mapping(address => bool) public claimed;
    bytes32 public merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev FIXED: Merkle proof allowlist instead of EOA check.
     *      Only addresses in the pre-computed allowlist can claim.
     *      This is immune to Sybil attacks from EOA farms.
     */
    function claimAirdrop(bytes32[] calldata proof) external {
        //  Merkle proof: only pre-approved addresses can claim
        require(_verifyProof(proof, merkleRoot, keccak256(abi.encodePacked(msg.sender))), "not in allowlist");
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        // Transfer airdrop amount...
    }

    function _verifyProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
        internal pure returns (bool)
    {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = computed < proof[i]
                ? keccak256(abi.encodePacked(computed, proof[i]))
                : keccak256(abi.encodePacked(proof[i], computed));
        }
        return computed == root;
    }

    function hasClaimed(address a) external view returns (bool) {
        return claimed[a];
    }
}

/**
 * @title PA03_ProperReentrancyGuard (FIXED)
 * @notice Fix for PA-03: use a proper reentrancy guard for ALL callers
 *
 * Do NOT use extcodesize for access control or reentrancy protection.
 * Use a mutex that applies to every caller regardless of code size.
 */
contract PA03_ProperReentrancyGuard {
    mapping(address => uint256) public deposits;
    //  Single mutex for ALL callers — no EOA carve-out
    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        //  Applies to EOAs and contracts alike
        require(_status != _ENTERED, "reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    /**
     * @dev FIXED: nonReentrant applies to ALL callers.
     *      A delegated EOA with a receive() hook cannot reenter
     *      because _status is already _ENTERED when the ETH transfer fires.
     */
    function withdraw(uint256 amount) external nonReentrant {
        require(deposits[msg.sender] >= amount, "insufficient");
        //  Checks-Effects-Interactions: update state BEFORE external call
        deposits[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
