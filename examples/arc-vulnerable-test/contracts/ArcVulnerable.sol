// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ArcVulnerable
 * @notice Test contract with intentional Arc-specific vulnerabilities
 * @dev Used to verify ArcShield rules ARC001-ARC027
 */

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IGatewayWallet {
    function deposit(address token, uint256 amount) external;
}

interface ITokenMessenger {
    function depositForBurn(
        uint256 amount,
        uint32 destinationDomain,
        bytes32 mintRecipient,
        address burnToken
    ) external returns (uint64);
}

contract ArcVulnerable {
    // Arc contract addresses
    address constant USDC = 0x3600000000000000000000000000000000000000;
    address constant EURC = 0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a;
    address constant USYC = 0xe9185F0c5F296Ed1797AaE4238D26CCaBEadb86C;
    address constant GatewayWallet = 0x0077777d7EBA4688BDeF3E311b846F25870A19B9;
    address constant FxEscrow = 0x1f91886C7028986aD885ffCee0e40b75C9cd5aC1;
    address constant Permit2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    address constant TokenMessenger = 0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA;

    uint256 public lastTimestamp;
    uint256 public cachedUSYCBalance;

    // ============================================
    // ARC001: Using block.prevrandao (always 0 on Arc)
    // ============================================
    function getRandomNumber() external view returns (uint256) {
        // BAD: block.prevrandao is always 0 on Arc
        return block.prevrandao;
    }

    function lottery() external view returns (bool) {
        // BAD: Using block.difficulty (alias for prevrandao)
        return block.difficulty % 2 == 0;
    }

    // ============================================
    // ARC002: Hardcoded 6 Decimal Assumption
    // ============================================
    function convertToUSDC(uint256 amount) external pure returns (uint256) {
        // BAD: Hardcoding 6 decimals - Arc native USDC uses 18!
        return amount * 10**6;
    }

    function transferAmount() external pure returns (uint256) {
        // BAD: Hardcoded 1e6 assumption
        return 1000000; // 1 USDC with 6 decimals - wrong for native!
    }

    // ============================================
    // ARC003: Strict Timestamp Comparison
    // ============================================
    function checkTime() external view returns (bool) {
        // BAD: Strict equality - multiple blocks can share timestamps on Arc
        return block.timestamp == lastTimestamp;
    }

    function requireFutureTime(uint256 deadline) external view {
        // BAD: Strict > comparison may fail
        require(block.timestamp > deadline, "Too early");
    }

    // ============================================
    // ARC004: Unnecessary Confirmation Waits
    // ============================================
    function waitForConfirmation(uint256 txBlock) external view returns (bool) {
        // BAD: Arc has instant finality - no need to wait
        return block.number > txBlock + 12;
    }

    // ============================================
    // ARC006: Missing USDC Blocklist Handling
    // ============================================
    function sendUSDC(address to, uint256 amount) external {
        // BAD: No try-catch for blocklist reverts
        IERC20(USDC).transfer(to, amount);
    }

    function sendFromUser(address from, address to, uint256 amount) external {
        // BAD: transferFrom without blocklist handling
        IERC20(USDC).transferFrom(from, to, amount);
    }

    // ============================================
    // ARC007: Mixed Decimal Interface Usage
    // ============================================
    function mixedDecimals() external payable {
        // BAD: Mixing msg.value (18 decimals) with 6 decimal calculation
        uint256 sixDecimals = msg.value / 10**12;
        uint256 balance = IERC20(USDC).balanceOf(address(this));
        require(balance >= sixDecimals * 10**6, "Not enough");
    }

    // ============================================
    // ARC016-018: USYC Issues
    // ============================================
    function cacheUSYCBalance() external {
        // BAD: Caching USYC balance - it changes over time (yield-bearing)
        cachedUSYCBalance = IERC20(USYC).balanceOf(address(this));
    }

    function sendUSYC(address to, uint256 amount) external {
        // BAD: No allowlist check via Entitlements contract
        IERC20(USYC).transfer(to, amount);
    }

    // ============================================
    // ARC019: Invalid CCTP Domain
    // ============================================
    function bridgeToEthereum(uint256 amount, bytes32 recipient) external {
        // Using CCTP - need to ensure correct domain
        uint32 destinationDomain = 0; // Ethereum domain
        ITokenMessenger(TokenMessenger).depositForBurn(
            amount,
            destinationDomain,
            recipient,
            USDC
        );
    }

    function bridgeToArc(uint256 amount, bytes32 recipient) external {
        // NOTE: If calling FROM another chain, Arc domain is 26
        uint32 sourceDomain = 26; // Arc domain
        // This would be called from another chain
    }

    // ============================================
    // ARC020: Gateway Transfer Instead of Deposit
    // ============================================
    function depositToGatewayWRONG(uint256 amount) external {
        // BAD: Using transfer instead of deposit - funds will be lost!
        IERC20(USDC).transfer(GatewayWallet, amount);
    }

    function depositToGatewayCORRECT(uint256 amount) external {
        // GOOD: Using proper deposit function
        IERC20(USDC).approve(GatewayWallet, amount);
        IGatewayWallet(GatewayWallet).deposit(USDC, amount);
    }

    // ============================================
    // ARC022: Missing Permit2 Deadline
    // ============================================
    function approveWithPermit2(address spender, uint256 amount) external {
        // Using Permit2 - should validate deadline
        IERC20(USDC).approve(Permit2, amount);
        // BAD: No deadline validation in permit signature
    }

    // ============================================
    // ARC023: FxEscrow Settlement
    // ============================================
    function settleEscrow() external {
        // Interacting with FxEscrow - timing matters
        // BAD: No timeout/expiry handling for StableFX escrow
    }

    // ============================================
    // ARC024: EURC Decimal Handling
    // ============================================
    function sendEURC(address to, uint256 amount) external {
        // EURC uses 6 decimals - be careful not to mix with native 18
        IERC20(EURC).transfer(to, amount);
    }

    // ============================================
    // ARC025: Blob Transaction (disabled on Arc)
    // ============================================
    function checkBlobHash() external view returns (bytes32) {
        // BAD: EIP-4844 blobs are disabled on Arc
        // This would fail: blobhash(0)
        return bytes32(0);
    }

    // ============================================
    // ARC010: Validator Set Dependency
    // ============================================
    function getBlockProducer() external view returns (address) {
        // BAD: Don't rely on coinbase behavior
        return block.coinbase;
    }

    // ============================================
    // ARC011: Native Token Handling
    // ============================================
    receive() external payable {
        // Native token on Arc is USDC (18 decimals), not ETH
        // msg.value will be in USDC with 18 decimals
    }

    function withdraw() external payable {
        // BAD: Assuming ETH semantics when it's actually USDC
        payable(msg.sender).transfer(address(this).balance);
    }
}

// ============================================
// ARC005: SELFDESTRUCT in Constructor
// ============================================
contract SelfDestructOnDeploy {
    constructor() payable {
        // BAD: SELFDESTRUCT reverts in constructor on Arc
        selfdestruct(payable(msg.sender));
    }
}
