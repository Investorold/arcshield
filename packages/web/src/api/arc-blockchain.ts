/**
 * Arc Blockchain Integration Module
 *
 * Handles on-chain transaction verification for USDC payments on Arc blockchain.
 *
 * Arc Blockchain Specifics:
 * - Native gas token: USDC
 * - USDC ERC20 decimals: 6
 * - Native balance decimals: 18
 * - Deterministic finality: <1s (no confirmation waits needed)
 * - RPC: https://rpc.testnet.arc.network
 */

import { createPublicClient, http, parseAbi, formatUnits, type Hash, type Address } from 'viem';

// Arc Testnet configuration
const ARC_TESTNET_CONFIG = {
  id: 26, // CCTP Domain ID
  name: 'Arc Testnet',
  network: 'arc-testnet',
  nativeCurrency: {
    name: 'USDC',
    symbol: 'USDC',
    decimals: 18, // Native balance uses 18 decimals
  },
  rpcUrls: {
    default: {
      http: ['https://rpc.testnet.arc.network'],
    },
  },
  blockExplorers: {
    default: {
      name: 'ArcScan',
      url: 'https://testnet.arcscan.app',
    },
  },
};

// USDC Contract on Arc (ERC20 interface uses 6 decimals)
const USDC_CONTRACT_ADDRESS = '0x3600000000000000000000000000000000000000' as Address;
const USDC_ERC20_DECIMALS = 6;

// ERC20 Transfer event ABI
const ERC20_TRANSFER_ABI = parseAbi([
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);

// Create Arc public client
const arcClient = createPublicClient({
  chain: ARC_TESTNET_CONFIG as any,
  transport: http(process.env.ARC_RPC_URL || ARC_TESTNET_CONFIG.rpcUrls.default.http[0]),
});

/**
 * Transaction verification result
 */
export interface TransactionVerificationResult {
  verified: boolean;
  error?: string;
  details?: {
    txHash: string;
    blockNumber: bigint;
    from: Address;
    to: Address;
    amount: string;
    amountRaw: bigint;
    timestamp?: number;
    status: 'success' | 'reverted';
  };
}

/**
 * Verify a USDC payment transaction on Arc blockchain
 *
 * @param txHash - Transaction hash to verify
 * @param expectedAmount - Expected USDC amount (in human-readable format, e.g., "0.10")
 * @param expectedTo - Expected recipient address (treasury)
 * @param expectedFrom - Optional: Expected sender address (wallet)
 * @returns Verification result with details
 */
export async function verifyTransactionOnChain(
  txHash: string,
  expectedAmount: number,
  expectedTo: string,
  expectedFrom?: string
): Promise<TransactionVerificationResult> {
  try {
    console.log(`[Arc] Verifying transaction: ${txHash}`);
    console.log(`[Arc] Expected: ${expectedAmount} USDC to ${expectedTo}`);

    // Normalize addresses to lowercase for comparison
    const normalizedExpectedTo = expectedTo.toLowerCase() as Address;
    const normalizedExpectedFrom = expectedFrom?.toLowerCase() as Address | undefined;

    // 1. Get transaction receipt
    const receipt = await arcClient.getTransactionReceipt({
      hash: txHash as Hash,
    });

    if (!receipt) {
      return {
        verified: false,
        error: 'Transaction not found on Arc blockchain. It may not be confirmed yet or the hash is invalid.',
      };
    }

    // 2. Check transaction status
    if (receipt.status !== 'success') {
      return {
        verified: false,
        error: 'Transaction was reverted on-chain',
        details: {
          txHash,
          blockNumber: receipt.blockNumber,
          from: receipt.from,
          to: receipt.to || ('' as Address),
          amount: '0',
          amountRaw: 0n,
          status: 'reverted',
        },
      };
    }

    // 3. Parse Transfer events from logs
    // Look for USDC Transfer events to our treasury
    let transferFound = false;
    let transferDetails: {
      from: Address;
      to: Address;
      value: bigint;
    } | null = null;

    for (const log of receipt.logs) {
      // Check if this log is from the USDC contract
      if (log.address.toLowerCase() !== USDC_CONTRACT_ADDRESS.toLowerCase()) {
        continue;
      }

      // Check if this is a Transfer event (topic[0] matches Transfer signature)
      // Transfer(address,address,uint256) signature
      const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

      if (log.topics[0] !== TRANSFER_TOPIC) {
        continue;
      }

      // Decode the Transfer event
      // topics[1] = from address (indexed)
      // topics[2] = to address (indexed)
      // data = value (uint256)
      const from = `0x${log.topics[1]?.slice(26)}`.toLowerCase() as Address;
      const to = `0x${log.topics[2]?.slice(26)}`.toLowerCase() as Address;
      const value = BigInt(log.data);

      console.log(`[Arc] Found Transfer: ${from} -> ${to}, value: ${value}`);

      // Check if this transfer is to our treasury
      if (to === normalizedExpectedTo) {
        transferFound = true;
        transferDetails = { from, to, value };
        break;
      }
    }

    if (!transferFound || !transferDetails) {
      return {
        verified: false,
        error: `No USDC transfer to treasury address ${expectedTo} found in transaction`,
      };
    }

    // 4. Verify the amount (USDC ERC20 uses 6 decimals)
    const expectedAmountRaw = BigInt(Math.round(expectedAmount * 10 ** USDC_ERC20_DECIMALS));
    const actualAmount = parseFloat(formatUnits(transferDetails.value, USDC_ERC20_DECIMALS));

    console.log(`[Arc] Expected amount raw: ${expectedAmountRaw}, Actual: ${transferDetails.value}`);

    // Allow for small rounding differences (within 0.0001 USDC)
    const tolerance = 0.0001;
    if (Math.abs(actualAmount - expectedAmount) > tolerance) {
      return {
        verified: false,
        error: `Amount mismatch: expected ${expectedAmount} USDC, got ${actualAmount} USDC`,
        details: {
          txHash,
          blockNumber: receipt.blockNumber,
          from: transferDetails.from,
          to: transferDetails.to,
          amount: actualAmount.toString(),
          amountRaw: transferDetails.value,
          status: 'success',
        },
      };
    }

    // 5. Optionally verify sender address
    if (normalizedExpectedFrom && transferDetails.from !== normalizedExpectedFrom) {
      return {
        verified: false,
        error: `Sender mismatch: expected ${expectedFrom}, got ${transferDetails.from}`,
        details: {
          txHash,
          blockNumber: receipt.blockNumber,
          from: transferDetails.from,
          to: transferDetails.to,
          amount: actualAmount.toString(),
          amountRaw: transferDetails.value,
          status: 'success',
        },
      };
    }

    // 6. Get block timestamp (optional, for additional verification)
    let timestamp: number | undefined;
    try {
      const block = await arcClient.getBlock({ blockNumber: receipt.blockNumber });
      timestamp = Number(block.timestamp);
    } catch {
      // Block timestamp is optional, continue without it
    }

    // All checks passed!
    console.log(`[Arc] Transaction verified successfully!`);

    return {
      verified: true,
      details: {
        txHash,
        blockNumber: receipt.blockNumber,
        from: transferDetails.from,
        to: transferDetails.to,
        amount: actualAmount.toString(),
        amountRaw: transferDetails.value,
        timestamp,
        status: 'success',
      },
    };
  } catch (error) {
    console.error('[Arc] Verification error:', error);

    // Handle specific error cases
    if (error instanceof Error) {
      if (error.message.includes('could not be found')) {
        return {
          verified: false,
          error: 'Transaction not found. Please ensure the transaction is confirmed on Arc blockchain.',
        };
      }
      if (error.message.includes('invalid hash')) {
        return {
          verified: false,
          error: 'Invalid transaction hash format',
        };
      }
    }

    return {
      verified: false,
      error: `Verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}

/**
 * Check if a transaction hash is valid format
 */
export function isValidTxHash(hash: string): boolean {
  return /^0x[a-fA-F0-9]{64}$/.test(hash);
}

/**
 * Get transaction details without verification
 */
export async function getTransactionDetails(txHash: string) {
  try {
    const receipt = await arcClient.getTransactionReceipt({
      hash: txHash as Hash,
    });

    if (!receipt) {
      return null;
    }

    const tx = await arcClient.getTransaction({
      hash: txHash as Hash,
    });

    return {
      hash: txHash,
      from: receipt.from,
      to: receipt.to,
      blockNumber: receipt.blockNumber,
      status: receipt.status,
      gasUsed: receipt.gasUsed,
      value: tx.value,
    };
  } catch {
    return null;
  }
}

/**
 * Get the Arc block explorer URL for a transaction
 */
export function getExplorerUrl(txHash: string): string {
  return `${ARC_TESTNET_CONFIG.blockExplorers.default.url}/tx/${txHash}`;
}

/**
 * Check if Arc RPC is reachable
 */
export async function checkArcConnection(): Promise<boolean> {
  try {
    const blockNumber = await arcClient.getBlockNumber();
    console.log(`[Arc] Connected to Arc blockchain at block ${blockNumber}`);
    return true;
  } catch (error) {
    console.error('[Arc] Failed to connect to Arc blockchain:', error);
    return false;
  }
}

export { USDC_CONTRACT_ADDRESS, USDC_ERC20_DECIMALS, ARC_TESTNET_CONFIG };
