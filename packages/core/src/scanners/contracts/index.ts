/**
 * Smart Contract Scanners
 *
 * Scanners for Solidity/EVM smart contracts:
 * - Slither wrapper (static analysis)
 * - Mythril wrapper (symbolic execution)
 * - Arc-specific rules
 */

// Contract scanners will be implemented in Phase 2
export const CONTRACT_SCANNERS = {
  slither: 'slither',
  mythril: 'mythril',
  arcSpecific: 'arc-specific',
} as const;
