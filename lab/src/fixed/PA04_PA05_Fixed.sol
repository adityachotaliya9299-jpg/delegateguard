// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PA04_SafeReentrancyGuard (FIXED)
 * @notice Fix for PA-04: proper reentrancy guard with CEI pattern
 * @author Aditya Chotaliya [adityachotaliya.xyz]
 *
 * Two fixes applied together:
 *   1. Checks-Effects-Interactions: zero balance BEFORE the external call
 *   2. Universal reentrancy guard: no EOA carve-out
 */
contract PA04_SafeReentrancyGuard {
    mapping(address => uint256) public balances;
    uint256 private _status;
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    constructor() { _status = _NOT_ENTERED; }

    modifier nonReentrant() {
        require(_status != _ENTERED, "reentrant");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @dev FIXED: CEI + universal nonReentrant.
     *      Even a delegated EOA with receive() logic cannot reenter:
     *      - _status is _ENTERED during the call
     *      - balance is already 0 before the call fires
     */
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // ✅ Effects before interactions
        balances[msg.sender] = 0;

        // ✅ External call after state update
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}

/**
 * @title PA05_MerkleAirdrop (FIXED)
 * @notice Fix for PA-05: Merkle allowlist replaces EOA-uniqueness assumption
 *
 * The only real fix for Sybil resistance is an off-chain verified allowlist
 * committed on-chain as a Merkle root. No on-chain check can reliably
 * identify "unique humans" — that requires off-chain attestation.
 */
contract PA05_MerkleAirdrop {
    bytes32 public immutable merkleRoot;
    mapping(address => bool) public hasClaimed;
    mapping(address => bool) public isRegisteredVoter;
    uint256 public totalVoters;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
    }

    /**
     * @dev FIXED: Merkle proof gates the airdrop.
     *      The allowlist is computed off-chain with Sybil filtering
     *      (e.g., on-chain activity thresholds, identity proofs, etc.)
     *      and committed as a Merkle root. EOA farms can't pass this.
     */
    function claimAirdrop(bytes32[] calldata proof) external {
        require(!hasClaimed[msg.sender], "already claimed");
        require(
            _verify(proof, merkleRoot, keccak256(abi.encodePacked(msg.sender))),
            "PA05: not in allowlist"
        );
        hasClaimed[msg.sender] = true;
        // Transfer tokens...
    }

    /**
     * @dev FIXED: Voter registration also requires Merkle proof.
     */
    function registerVoter(bytes32[] calldata proof) external {
        require(!isRegisteredVoter[msg.sender], "already registered");
        require(
            _verify(proof, merkleRoot, keccak256(abi.encodePacked(msg.sender))),
            "PA05: not eligible"
        );
        isRegisteredVoter[msg.sender] = true;
        totalVoters++;
    }

    function _verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf)
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
}
