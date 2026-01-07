// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * VulnerableVault - A deliberately vulnerable contract for testing ArcShield
 *
 * This contract contains multiple security issues that ArcShield should detect:
 * - Arc-specific vulnerabilities
 * - Common Solidity vulnerabilities
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

contract VulnerableVault {
    address public owner;
    IERC20 public usdc;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lastWithdrawTime;

    uint256 public constant USDC_DECIMALS = 6; // ARC002: Wrong! Arc uses 18 decimals
    uint256 public constant MIN_DEPOSIT = 100 * 1e6; // ARC002: Hardcoded 6 decimals

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);
    event RandomWinner(address indexed winner, uint256 prize);

    constructor(address _usdc) {
        owner = msg.sender;
        usdc = IERC20(_usdc);

        // ARC005: SELFDESTRUCT in constructor - reverts on Arc!
        // Uncomment to trigger: selfdestruct(payable(owner));
    }

    /**
     * Deposit USDC into the vault
     */
    function deposit(uint256 amount) external {
        require(amount >= MIN_DEPOSIT, "Below minimum deposit");

        // Vulnerable: No return value check (Slither: unchecked-transfer)
        usdc.transferFrom(msg.sender, address(this), amount);

        // ARC006: No blocklist check for USDC transfers
        deposits[msg.sender] += amount;

        emit Deposit(msg.sender, amount);
    }

    /**
     * Withdraw funds - has reentrancy vulnerability
     */
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");

        // Vulnerable: State change after external call (reentrancy)
        usdc.transfer(msg.sender, amount);
        deposits[msg.sender] -= amount;

        emit Withdraw(msg.sender, amount);
    }

    /**
     * Pick a random winner - uses insecure randomness
     */
    function pickRandomWinner(address[] calldata participants) external {
        require(msg.sender == owner, "Not owner");
        require(participants.length > 0, "No participants");

        // ARC001: block.prevrandao is ALWAYS 0 on Arc - completely predictable!
        uint256 randomIndex = uint256(
            keccak256(abi.encodePacked(block.prevrandao, block.timestamp))
        ) % participants.length;

        address winner = participants[randomIndex];
        uint256 prize = usdc.balanceOf(address(this)) / 10;

        usdc.transfer(winner, prize);

        emit RandomWinner(winner, prize);
    }

    /**
     * Time-locked withdrawal - has timestamp issues
     */
    function timedWithdraw() external {
        // ARC003: Strict timestamp comparison - may fail on Arc
        // Multiple blocks can have same timestamp
        require(block.timestamp == lastWithdrawTime[msg.sender] + 1 days, "Not exact time");

        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        lastWithdrawTime[msg.sender] = block.timestamp;

        usdc.transfer(msg.sender, amount);
    }

    /**
     * Wait for confirmations - unnecessary on Arc
     */
    function safeTransfer(address to, uint256 amount) external {
        require(msg.sender == owner, "Not owner");

        // ARC004: Unnecessary confirmation waits - Arc has instant finality
        // This comment triggers the detector:
        // Wait for 12 block confirmations before proceeding
        require(block.number > 0, "waiting for confirmations");

        usdc.transfer(to, amount);
    }

    /**
     * Get deposit in USD value - wrong decimal calculation
     */
    function getDepositValueUSD(address user) external view returns (uint256) {
        // ARC002 & ARC007: Using wrong decimals
        // Arc USDC has 18 decimals, not 6!
        uint256 balance = deposits[user];
        return balance / 1e6; // Wrong! Should be 1e18 on Arc
    }

    /**
     * Emergency withdraw - uses tx.origin (vulnerable)
     */
    function emergencyWithdraw() external {
        // Slither: tx-origin vulnerability
        require(tx.origin == owner, "Not owner");

        uint256 balance = usdc.balanceOf(address(this));
        usdc.transfer(owner, balance);
    }

    /**
     * Self destruct - dangerous function
     */
    function destroy() external {
        require(msg.sender == owner, "Not owner");
        // Slither: suicidal
        selfdestruct(payable(owner));
    }
}
