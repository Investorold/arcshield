/**
 * Slither Integration
 *
 * Runs Slither static analysis on Solidity smart contracts
 * and parses the results into ArcShield vulnerability format.
 */

import { spawn } from 'child_process';
import * as path from 'path';
import type { SmartContractVulnerability, Severity } from '../types/index.js';

// Map Slither impact to our severity levels
const IMPACT_TO_SEVERITY: Record<string, Severity> = {
  'High': 'high',
  'Medium': 'medium',
  'Low': 'low',
  'Informational': 'info',
  'Optimization': 'info',
};

// Map Slither confidence levels
const CONFIDENCE_LEVELS = ['High', 'Medium', 'Low'];

interface SlitherResult {
  success: boolean;
  error?: string;
  results?: {
    detectors: SlitherDetector[];
  };
}

interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: SlitherElement[];
  first_markdown_element?: string;
  id?: string;
}

interface SlitherElement {
  type: string;
  name: string;
  source_mapping: {
    filename_relative: string;
    lines: number[];
    starting_column: number;
    ending_column: number;
  };
  type_specific_fields?: {
    parent?: {
      name: string;
    };
  };
}

/**
 * Check if Slither is installed
 */
export async function isSlitherInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('slither', ['--version']);
    proc.on('close', (code) => resolve(code === 0));
    proc.on('error', () => resolve(false));
  });
}

/**
 * Run Slither on a directory containing Solidity files
 */
export async function runSlither(
  targetDir: string,
  excludePaths: string[] = ['node_modules', 'lib', 'test']
): Promise<SmartContractVulnerability[]> {
  const vulnerabilities: SmartContractVulnerability[] = [];

  // Check if Slither is installed
  const installed = await isSlitherInstalled();
  if (!installed) {
    console.log('[Slither] Not installed - skipping smart contract analysis');
    console.log('[Slither] Install with: pip install slither-analyzer');
    return vulnerabilities;
  }

  // Build exclude args
  const excludeArgs = excludePaths.flatMap(p => ['--filter-paths', p]);

  // Run Slither with JSON output
  const result = await runSlitherProcess(targetDir, excludeArgs);

  if (!result.success) {
    if (result.error?.includes('No contract found')) {
      console.log('[Slither] No Solidity contracts found');
    } else {
      console.log(`[Slither] Error: ${result.error}`);
    }
    return vulnerabilities;
  }

  // Parse detectors into vulnerabilities
  if (result.results?.detectors) {
    let vulnId = 1;
    for (const detector of result.results.detectors) {
      const vuln = parseDetector(detector, vulnId++);
      if (vuln) {
        vulnerabilities.push(vuln);
      }
    }
  }

  return vulnerabilities;
}

/**
 * Execute Slither process
 */
function runSlitherProcess(
  targetDir: string,
  additionalArgs: string[] = []
): Promise<SlitherResult> {
  return new Promise((resolve) => {
    const args = [
      targetDir,
      '--json', '-',  // Output JSON to stdout
      ...additionalArgs,
    ];

    const proc = spawn('slither', args, {
      cwd: targetDir,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      if (code !== 0 && !stdout) {
        resolve({
          success: false,
          error: stderr || `Slither exited with code ${code}`,
        });
        return;
      }

      try {
        const parsed = JSON.parse(stdout);
        resolve({
          success: true,
          results: parsed,
        });
      } catch {
        resolve({
          success: false,
          error: `Failed to parse Slither output: ${stdout.substring(0, 200)}`,
        });
      }
    });

    proc.on('error', (err) => {
      resolve({
        success: false,
        error: err.message,
      });
    });
  });
}

/**
 * Parse a Slither detector result into our vulnerability format
 */
function parseDetector(
  detector: SlitherDetector,
  vulnId: number
): SmartContractVulnerability | null {
  // Get the first element with source mapping
  const element = detector.elements?.find(e => e.source_mapping);
  if (!element) return null;

  const severity = IMPACT_TO_SEVERITY[detector.impact] || 'info';
  const filePath = element.source_mapping.filename_relative;
  const lineNumber = element.source_mapping.lines[0] || 1;

  // Get contract and function name
  const contractName = element.type_specific_fields?.parent?.name ||
                       element.name ||
                       'Unknown';
  const functionName = element.type === 'function' ? element.name : undefined;

  return {
    id: `SC-${String(vulnId).padStart(3, '0')}`,
    title: formatDetectorName(detector.check),
    severity,
    threatId: '', // Will be linked later
    description: detector.description,
    filePath,
    lineNumber,
    codeSnippet: detector.first_markdown_element || '',
    exploitability: `Confidence: ${detector.confidence}`,
    remediation: getRemediationForDetector(detector.check),
    aiFixPrompt: `Fix the ${detector.check} vulnerability in ${filePath}`,
    contractName,
    functionName,
    detector: detector.check,
    tool: 'slither',
  };
}

/**
 * Format detector name for display
 */
function formatDetectorName(check: string): string {
  return check
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/**
 * Get remediation advice for common Slither detectors
 */
function getRemediationForDetector(check: string): string {
  const remediations: Record<string, string> = {
    'reentrancy-eth': 'Use the checks-effects-interactions pattern. Consider using ReentrancyGuard from OpenZeppelin.',
    'reentrancy-no-eth': 'Apply the checks-effects-interactions pattern even for non-ETH reentrancy.',
    'uninitialized-state': 'Initialize all state variables in the constructor.',
    'uninitialized-local': 'Initialize all local variables before use.',
    'arbitrary-send-eth': 'Validate recipient addresses and use pull over push pattern for ETH transfers.',
    'controlled-delegatecall': 'Never use user-controlled addresses in delegatecall.',
    'suicidal': 'Add access control to selfdestruct or remove it entirely.',
    'unchecked-transfer': 'Use SafeERC20 library or check return values of transfer/transferFrom.',
    'locked-ether': 'Add a withdraw function or remove payable modifier if ETH is not needed.',
    'tx-origin': 'Replace tx.origin with msg.sender for authentication.',
    'timestamp': 'Avoid using block.timestamp for critical logic. Consider using block numbers.',
    'weak-prng': 'Use a verifiable random function (VRF) like Chainlink VRF instead of block variables.',
    'shadowing-state': 'Rename variables to avoid shadowing inherited state variables.',
    'missing-zero-check': 'Add require(address != address(0)) checks for address parameters.',
  };

  return remediations[check] || 'Review the code and apply secure coding practices.';
}

/**
 * Get list of common Slither detectors
 */
export function getSlitherDetectors(): string[] {
  return [
    'reentrancy-eth',
    'reentrancy-no-eth',
    'reentrancy-benign',
    'uninitialized-state',
    'uninitialized-local',
    'arbitrary-send-eth',
    'controlled-delegatecall',
    'suicidal',
    'unchecked-transfer',
    'locked-ether',
    'tx-origin',
    'timestamp',
    'weak-prng',
    'shadowing-state',
    'missing-zero-check',
  ];
}
