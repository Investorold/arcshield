# Arc Blockchain - Complete Developer Reference

> **Last Updated:** January 2026
> **Network Status:** Testnet
> **Purpose:** Reference guide for ArcShield security rules and future Arc dApp development

---

## Table of Contents

1. [Arc Overview](#arc-overview)
2. [Core Principles](#core-principles)
3. [Contract Addresses](#contract-addresses)
4. [EVM Compatibility & Differences](#evm-compatibility--differences)
5. [Architecture](#architecture)
6. [Key Features](#key-features)
7. [Security Considerations](#security-considerations)
8. [Tools & Ecosystem](#tools--ecosystem)
9. [Development Guides](#development-guides)

---

## Arc Overview

Arc is an **open Layer-1 blockchain** purpose-built to unite programmable money and onchain innovation with real-world economic activity. It serves as the **"Economic OS for the internet"**.

### What Arc Enables
- Onchain lending and capital markets
- Foreign exchange (FX) and stablecoin swaps
- Cross-border payments and payouts
- Agentic commerce (AI-mediated transactions)
- Tokenized securities and collateral management

### Key Differentiators
| Feature | Arc | Ethereum |
|---------|-----|----------|
| Native Gas Token | **USDC** (stable) | ETH (volatile) |
| Finality | **Deterministic <1s** | Probabilistic (~12-15 min) |
| Fee Target | **~$0.01 per tx** | Variable, often $1-50+ |
| Consensus | Malachite (Tendermint BFT) | Proof-of-Stake |
| Validators | Permissioned (regulated institutions) | Permissionless |

---

## Core Principles

1. **Purpose-built, not general-purpose** - Optimized for financial use cases
2. **Open and composable by default** - Public EVM-compatible network
3. **Market-neutral and multichain-aligned** - CCTP for cross-chain liquidity
4. **Built to coordinate, not control** - Decentralized but compliant
5. **Trusted infrastructure, end-to-end** - Circle's full-stack platform integration

---

## Contract Addresses

### Stablecoins

#### USDC (Native Gas Token)
```
Address: 0x3600000000000000000000000000000000000000
Decimals: 6 (ERC20 interface) / 18 (native balance)
```

**CRITICAL:** Arc has TWO decimal representations for USDC:
- **Native balance:** 18 decimals (like ETH on Ethereum)
- **ERC20 interface:** 6 decimals (standard USDC)

> Never mix these values directly - use `decimals()` function always!

#### EURC (Euro Stablecoin)
```
Address: 0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a
Decimals: 6
```

#### USYC (Yield-Bearing Token)
```
Token:        0xe9185F0c5F296Ed1797AaE4238D26CCaBEadb86C (6 decimals)
Entitlements: 0xcc205224862c7641930c87679e98999d23c26113
Teller:       0x9fdF14c5B14173D74C08Af27AebFf39240dC105A
```

**USYC Properties:**
- Represents tokenized money market fund shares
- Backed by short-duration U.S. Treasury securities
- **Requires allowlisting** via Circle Support (24-48 hours)
- Balance can change over time (yield-bearing)

---

### Cross-Chain (CCTP & Gateway)

#### CCTP Contracts (Domain 26)
| Contract | Address |
|----------|---------|
| TokenMessengerV2 | `0x8FE6B999Dc680CcFDD5Bf7EB0974218be2542DAA` |
| MessageTransmitterV2 | `0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275` |
| TokenMinterV2 | `0xb43db544E2c27092c107639Ad201b3dEfAbcF192` |
| MessageV2 | `0xbaC0179bB358A8936169a63408C8481D582390C4` |

**Arc's CCTP Domain ID: 26**

Other chain domains for reference:
- Ethereum: 0
- Avalanche: 1
- Base: 6

#### Gateway Contracts (Chain-Abstracted USDC)
| Contract | Address |
|----------|---------|
| GatewayWallet | `0x0077777d7EBA4688BDeF3E311b846F25870A19B9` |
| GatewayMinter | `0x0022222ABE238Cc2C7Bb1f21003F0a260052475B` |

**Gateway enables:**
- Unified USDC balance across multiple chains
- Deposit from any supported chain
- Withdraw/mint to any supported chain
- Uses EIP-712 typed data for burn intents

---

### Payments & Settlement

#### StableFX
```
FxEscrow: 0x1f91886C7028986aD885ffCee0e40b75C9cd5aC1
```

**StableFX is:**
- Enterprise-grade stablecoin FX engine
- Request-for-Quote (RFQ) execution
- Onchain settlement using escrow
- **Requires Permit2 allowance for USDC**

---

### Common Ethereum Contracts

| Contract | Address | Purpose |
|----------|---------|---------|
| CREATE2 Factory | `0x4e59b44847b379578588920cA78FbF26c0B4956C` | Deterministic deployment |
| Multicall3 | `0xcA11bde05977b3631167028862bE2a173976CA11` | Batched read calls |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Signature-based approvals |

---

## EVM Compatibility & Differences

Arc targets **Prague EVM hard fork** with these differences:

### Critical Differences from Ethereum

| Area | Ethereum | Arc | Security Implication |
|------|----------|-----|---------------------|
| **Native token** | ETH (volatile) | USDC (stable, 18 decimals native) | Different decimal handling |
| **ERC20 USDC** | 6 decimals | 6 decimals | Must not mix with native 18 decimals |
| **`block.prevrandao`** | Random value | **Always 0** | Cannot use for randomness |
| **Finality** | Probabilistic | **Deterministic <1s** | No confirmation waits needed |
| **Block timestamps** | Strictly increasing | **Can share timestamps** | Don't assume strictly increasing |
| **SELFDESTRUCT** | Allowed | **Reverts in constructor** | Cannot self-destruct during deployment |
| **USDC blocklist** | N/A | **Pre and post-execution checks** | Transactions can revert if blocklisted |
| **EIP-4844 blobs** | Supported | **Disabled** | No blob transactions |

### USDC Blocklist Behavior

1. **Pre-mempool:** If sender is blocklisted → transaction rejected (no fees)
2. **Post-mempool:** If blocklisted after acceptance → reverts at runtime (gas consumed)
3. **Runtime transfer:** If transfer to/from blocklisted address → operation reverts (fees collected)

### Code Patterns to Avoid

```solidity
// BAD: Using prevrandao for randomness (always 0 on Arc)
uint256 random = block.prevrandao;

// BAD: Assuming timestamps strictly increase
require(block.timestamp > lastTimestamp, "Time must increase");

// BAD: Hardcoding 6 decimals for native USDC
uint256 amount = userInput * 1e6; // Wrong for native balance!

// BAD: Waiting for confirmations (unnecessary on Arc)
require(block.number > txBlock + 12, "Wait for confirmations");

// BAD: SELFDESTRUCT in constructor
constructor() {
    selfdestruct(payable(msg.sender)); // Will revert on Arc
}

// BAD: Not handling USDC blocklist
function transfer(address to, uint256 amount) external {
    // Should check if address is blocklisted first
    usdc.transfer(to, amount);
}
```

### Correct Patterns for Arc

```solidity
// GOOD: Use external VRF for randomness
uint256 random = IChainlinkVRF(vrfCoordinator).getRandomNumber();

// GOOD: Use >= for timestamp comparisons
require(block.timestamp >= requiredTime, "Too early");

// GOOD: Use decimals() function
uint256 decimals = IERC20Metadata(token).decimals();
uint256 amount = userInput * (10 ** decimals);

// GOOD: No confirmation waits needed
// Transaction is final immediately after inclusion

// GOOD: Handle blocklist reverts gracefully
try usdc.transfer(to, amount) {
    // Success
} catch {
    // Handle blocklist or other failure
}
```

---

## Architecture

### Consensus Layer: Malachite

**Malachite** is a high-performance implementation of **Tendermint BFT** consensus.

#### How It Works
1. **Propose:** Validator proposes a block
2. **Pre-vote:** Validators vote on validity
3. **Pre-commit:** Second voting round
4. **Commit:** Block finalized if >2/3 pre-commit

#### Performance
- **3,000+ TPS** with 20 globally distributed validators
- **<350ms finality** under benchmark conditions
- **>10,000 TPS** with 4 validators

#### Proof-of-Authority
- Validators are **regulated institutions**
- Geographic distribution for resilience
- Operational requirements: uptime SLAs, SOC 2 certification
- Block production rotated for fairness

### Execution Layer: Reth

Arc's execution layer is based on **Reth** (Rust Ethereum client).

#### Components
1. **Transaction Pool:** Pending transactions
2. **EVM Execution:** Smart contracts & transfers
3. **Fee Manager:** USDC-based gas accounting
4. **Privacy Module:** Confidential transfers (planned)
5. **Stablecoin Services:** Multi-currency support (planned)
6. **Ledger & State:** Accounts, balances, contracts

---

## Key Features

### 1. Stable Fee Design

**Target: ~$0.01 per transaction**

- USDC as unit of account (no price volatility)
- Fee smoothing via EWMA (exponentially weighted moving average)
- Fees adjust gradually, not abruptly
- Short-term demand spikes have less impact

**Formula:**
```
fee = gas_units × base_fee_in_USDC
```

### 2. Deterministic Finality

- Transaction is either **unconfirmed** or **final**
- No "probably final" state
- Once final, **cannot be reversed**
- No chain reorganizations possible

**Developer benefit:** No rollback logic needed, instant settlement guarantees.

### 3. Opt-in Privacy (Planned)

- Confidential transfers (amounts encrypted)
- Sender/receiver addresses remain visible
- View keys for selective disclosure
- Compliance-ready (auditors can review when required)

**Technologies planned:**
- Trusted Execution Environments (TEEs)
- Multi-Party Computation (MPC)
- Fully Homomorphic Encryption (FHE)
- Zero-knowledge proofs (ZK)

---

## Security Considerations

### ArcShield Rules Reference

| Rule | Issue | Description |
|------|-------|-------------|
| ARC001 | `block.prevrandao` usage | Always 0 on Arc - cannot use for randomness |
| ARC002 | Hardcoded 6 decimals | Arc native balance uses 18 decimals |
| ARC003 | Strict timestamp comparison | Blocks can share timestamps on Arc |
| ARC004 | Unnecessary confirmation waits | Arc has instant finality |
| ARC005 | SELFDESTRUCT in constructor | Reverts on Arc |
| ARC006 | Missing USDC blocklist handling | USDC transfers can revert if blocklisted |
| ARC007 | Mixed decimal interface usage | Don't mix 6 and 18 decimal values |

### Additional Security Considerations

| Category | Consideration |
|----------|---------------|
| **USYC** | Uses 6 decimals; requires allowlisting; balance changes over time (yield) |
| **CCTP** | Validate domain ID (Arc = 26); verify message attestations |
| **Gateway** | Must use `deposit()` not `transfer()`; EIP-712 signature validation |
| **StableFX** | Requires Permit2 allowance; escrow timing considerations |
| **Permit2** | Signature replay protection; deadline validation |

---

## Tools & Ecosystem

### Account Abstraction Providers
| Provider | Features |
|----------|----------|
| Biconomy | Modular smart accounts, paymasters, bundlers |
| Circle Wallets | Dev-controlled wallets, full Circle integration |
| Privy | Embedded wallets, email/social login |
| Dynamic | Passkey wallets, flexible signer management |
| Thirdweb | Full-stack toolkit, managed smart wallet |
| Zerodev | ERC-4337 smart accounts, session keys |
| Pimlico | Bundler and paymaster infrastructure |

### Block Explorers
- **Blockscout:** https://testnet.arcscan.app

### Compliance
- **Elliptic:** Blockchain analytics, AML monitoring
- **TRM Labs:** Risk intelligence, wallet screening

### Data Indexers
- **Envio:** HyperIndex, event streaming
- **Goldsky:** Subgraphs, Mirror data pipelines
- **The Graph:** Decentralized indexing
- **Thirdweb Insight:** Data retrieval and transformation

### Node Providers
- **Alchemy:** Enhanced APIs, monitoring
- **QuickNode:** High-performance endpoints
- **dRPC:** Decentralized RPC aggregator
- **Blockdaemon:** Institutional-grade infrastructure

---

## Development Guides

### Quick Start: Deploy on Arc

```bash
# 1. Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 2. Initialize project
forge init hello-arc && cd hello-arc

# 3. Configure environment
echo 'ARC_TESTNET_RPC_URL="https://rpc.testnet.arc.network"' > .env

# 4. Deploy contract
forge create src/Contract.sol:Contract \
  --rpc-url $ARC_TESTNET_RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast
```

### Get Testnet USDC
1. Visit https://faucet.circle.com
2. Select "Arc Testnet"
3. Enter wallet address
4. Request USDC

### Bridge USDC to Arc (via CCTP)

```typescript
import { BridgeKit } from "@circle-fin/bridge-kit";

const kit = new BridgeKit();
await kit.bridge({
  from: { adapter, chain: "Ethereum_Sepolia" },
  to: { adapter, chain: "Arc_Testnet" },
  amount: "10.00",
});
```

### Gateway: Unified Crosschain Balance

```typescript
// Deposit to Gateway (NOT transfer!)
await client.createContractExecutionTransaction({
  walletId: WALLET_ID,
  contractAddress: GATEWAY_WALLET_ADDRESS,
  abiFunctionSignature: "deposit(address,uint256)",
  abiParameters: [USDC_ADDRESS, amount],
});
```

### Circle Dev-Controlled Wallets

```typescript
import { initiateDeveloperControlledWalletsClient } from "@circle-fin/developer-controlled-wallets";

const client = initiateDeveloperControlledWalletsClient({
  apiKey: process.env.API_KEY,
  entitySecret: process.env.ENTITY_SECRET,
});

// Create wallet on Arc
const wallets = await client.createWallets({
  blockchains: ["ARC-TESTNET"],
  count: 1,
  walletSetId: walletSetId,
});
```

---

## Network Information

| Property | Value |
|----------|-------|
| **Network Name** | Arc Testnet |
| **RPC URL** | https://rpc.testnet.arc.network |
| **Chain ID** | (Check explorer) |
| **CCTP Domain** | 26 |
| **Native Token** | USDC |
| **Block Explorer** | https://testnet.arcscan.app |
| **Faucet** | https://faucet.circle.com |

---

## Summary: Building Secure dApps on Arc

### DO:
- Use `decimals()` function for all token amounts
- Handle USDC blocklist reverts gracefully
- Use external VRF for randomness
- Treat transactions as final immediately
- Use `>=` for timestamp comparisons
- Validate CCTP domain IDs
- Use Gateway's `deposit()` function (not `transfer()`)

### DON'T:
- Mix 6 and 18 decimal representations
- Use `block.prevrandao` for randomness
- Wait for multiple confirmations
- Assume strictly increasing timestamps
- Use SELFDESTRUCT in constructors
- Ignore USYC allowlist requirements
- Skip Permit2 setup for StableFX

---

*This document is maintained as part of the ArcShield project for reference during security scanning and dApp development on Arc blockchain.*
