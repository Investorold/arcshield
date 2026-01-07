// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * UnsafeToken - Another vulnerable contract for testing
 *
 * Contains additional vulnerability patterns
 */

contract UnsafeToken {
    string public name = "Unsafe Token";
    string public symbol = "UNSAFE";
    uint8 public decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public totalSupply;
    address public owner;

    // Uninitialized state variable (Slither: uninitialized-state)
    address public pendingOwner;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");

        // Missing zero address check (Slither: missing-zero-check)
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;

        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");

        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;

        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * Mint new tokens - weak randomness for distribution
     */
    function mintRandom(address[] calldata recipients) external {
        require(msg.sender == owner, "Not owner");

        for (uint i = 0; i < recipients.length; i++) {
            // ARC001: block.difficulty is same as prevrandao, always 0 on Arc
            uint256 amount = uint256(
                keccak256(abi.encodePacked(block.difficulty, i))
            ) % 1000;

            balanceOf[recipients[i]] += amount;
            totalSupply += amount;
        }
    }

    /**
     * Airdrop with timestamp check
     */
    function airdrop(address recipient, uint256 amount) external {
        require(msg.sender == owner, "Not owner");

        // ARC003: Strict equality with timestamp
        if (block.timestamp == 0) {
            revert("Invalid timestamp");
        }

        balanceOf[recipient] += amount;
        totalSupply += amount;
    }

    /**
     * Locked ether - contract can receive but not send ETH
     */
    receive() external payable {
        // Slither: locked-ether - no way to withdraw ETH
    }

    /**
     * Dangerous delegatecall
     */
    function execute(address target, bytes calldata data) external {
        require(msg.sender == owner, "Not owner");
        // Slither: controlled-delegatecall
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}
