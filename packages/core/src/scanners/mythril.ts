/**
 * Mythril Integration
 *
 * Runs Mythril symbolic execution analysis on Solidity smart contracts
 * and parses the results into ArcShield vulnerability format.
 *
 * Mythril detects:
 * - Integer overflow/underflow
 * - Reentrancy vulnerabilities
 * - Unprotected ether withdrawal
 * - Unchecked call return values
 * - Delegatecall to user-supplied address
 * - And more...
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { SmartContractVulnerability, Severity } from '../types/index.js';

// Map Mythril severity to our severity levels
const SEVERITY_MAP: Record<string, Severity> = {
  'High': 'high',
  'Medium': 'medium',
  'Low': 'low',
};

// Map SWC IDs to human-readable names and remediations
const SWC_INFO: Record<string, { name: string; remediation: string }> = {
  'SWC-101': {
    name: 'Integer Overflow and Underflow',
    remediation: 'Use SafeMath library or Solidity 0.8+ with built-in overflow checks.',
  },
  'SWC-104': {
    name: 'Unchecked Call Return Value',
    remediation: 'Always check the return value of low-level calls and handle failures.',
  },
  'SWC-105': {
    name: 'Unprotected Ether Withdrawal',
    remediation: 'Add access control (onlyOwner, role-based) to withdrawal functions.',
  },
  'SWC-106': {
    name: 'Unprotected SELFDESTRUCT',
    remediation: 'Add access control to selfdestruct or remove it entirely.',
  },
  'SWC-107': {
    name: 'Reentrancy',
    remediation: 'Use checks-effects-interactions pattern and ReentrancyGuard.',
  },
  'SWC-110': {
    name: 'Assert Violation',
    remediation: 'Use require() for input validation, assert() only for invariants.',
  },
  'SWC-112': {
    name: 'Delegatecall to Untrusted Callee',
    remediation: 'Never delegatecall to user-controlled addresses.',
  },
  'SWC-113': {
    name: 'DoS with Failed Call',
    remediation: 'Use pull over push pattern for sending ETH.',
  },
  'SWC-114': {
    name: 'Transaction Order Dependence',
    remediation: 'Use commit-reveal schemes or other frontrunning mitigations.',
  },
  'SWC-115': {
    name: 'Authorization through tx.origin',
    remediation: 'Replace tx.origin with msg.sender for authentication.',
  },
  'SWC-116': {
    name: 'Block Timestamp Dependence',
    remediation: 'Avoid using block.timestamp for critical logic.',
  },
  'SWC-120': {
    name: 'Weak Sources of Randomness',
    remediation: 'Use Chainlink VRF or other verifiable randomness sources.',
  },
  'SWC-123': {
    name: 'Requirement Violation',
    remediation: 'Review the require statement logic and ensure valid inputs.',
  },
  'SWC-124': {
    name: 'Write to Arbitrary Storage Location',
    remediation: 'Validate array indices and storage slot calculations.',
  },
  'SWC-127': {
    name: 'Arbitrary Jump with Function Type Variable',
    remediation: 'Avoid using function type variables with user input.',
  },
};

interface MythrilIssue {
  swcID: string;
  swcTitle: string;
  severity: string;
  description: string;
  address: number;
  contract: string;
  function: string;
  filename: string;
  lineno: number;
  code?: string;
  sourceMap?: string;
  tx_sequence?: string;
}

interface MythrilResult {
  success: boolean;
  error?: string;
  issues?: MythrilIssue[];
}

/**
 * Check if Mythril is installed
 */
export async function isMythrilInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('myth', ['version']);
    proc.on('close', (code) => resolve(code === 0));
    proc.on('error', () => resolve(false));
  });
}

/**
 * Run Mythril on Solidity files in a directory
 */
export async function runMythril(
  targetDir: string,
  options: {
    timeout?: number;
    maxDepth?: number;
    solcVersion?: string;
  } = {}
): Promise<SmartContractVulnerability[]> {
  const vulnerabilities: SmartContractVulnerability[] = [];

  // Check if Mythril is installed
  const installed = await isMythrilInstalled();
  if (!installed) {
    console.log('[Mythril] Not installed - skipping symbolic execution');
    console.log('[Mythril] Install with: pip install mythril');
    return vulnerabilities;
  }

  // Find all Solidity files (exclude libs and tests)
  const solFiles = findSolidityFiles(targetDir);
  if (solFiles.length === 0) {
    console.log('[Mythril] No Solidity files found');
    return vulnerabilities;
  }

  console.log(`[Mythril] Analyzing ${solFiles.length} contract(s)...`);

  // Analyze each file
  let vulnId = 1;
  for (const solFile of solFiles) {
    const result = await analyzeSolidityFile(solFile, targetDir, options);

    if (result.success && result.issues) {
      for (const issue of result.issues) {
        const vuln = parseIssue(issue, vulnId++, targetDir);
        if (vuln) {
          vulnerabilities.push(vuln);
        }
      }
    } else if (result.error && !result.error.includes('No issues')) {
      console.log(`[Mythril] Warning: ${path.basename(solFile)} - ${result.error}`);
    }
  }

  return vulnerabilities;
}

/**
 * Find Solidity files in a directory
 */
function findSolidityFiles(dir: string): string[] {
  const solFiles: string[] = [];
  const excludeDirs = ['node_modules', 'lib', 'test', 'tests', 'mock', 'mocks'];

  function walkDir(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        if (!excludeDirs.includes(entry.name.toLowerCase())) {
          walkDir(fullPath);
        }
      } else if (entry.isFile() && entry.name.endsWith('.sol')) {
        solFiles.push(fullPath);
      }
    }
  }

  try {
    walkDir(dir);
  } catch {
    // Directory might not exist
  }

  return solFiles;
}

/**
 * Analyze a single Solidity file with Mythril
 */
function analyzeSolidityFile(
  filePath: string,
  targetDir: string,
  options: {
    timeout?: number;
    maxDepth?: number;
    solcVersion?: string;
  }
): Promise<MythrilResult> {
  return new Promise((resolve) => {
    const timeout = options.timeout || 300; // 5 minutes default
    const maxDepth = options.maxDepth || 22;

    const args = [
      'analyze',
      filePath,
      '--json',
      '--execution-timeout', String(timeout),
      '--max-depth', String(maxDepth),
    ];

    // Add solc version if specified
    if (options.solcVersion) {
      args.push('--solv', options.solcVersion);
    }

    const proc = spawn('myth', args, {
      cwd: targetDir,
      timeout: (timeout + 60) * 1000, // Add 60s buffer
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
      // Mythril returns 0 even with issues found
      try {
        if (stdout.trim()) {
          const parsed = JSON.parse(stdout);
          resolve({
            success: true,
            issues: parsed.issues || [],
          });
        } else {
          resolve({
            success: true,
            issues: [],
          });
        }
      } catch {
        resolve({
          success: false,
          error: stderr || `Failed to parse output: ${stdout.substring(0, 100)}`,
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
 * Parse a Mythril issue into our vulnerability format
 */
function parseIssue(
  issue: MythrilIssue,
  vulnId: number,
  targetDir: string
): SmartContractVulnerability | null {
  const swcInfo = SWC_INFO[issue.swcID] || {
    name: issue.swcTitle || 'Unknown Vulnerability',
    remediation: 'Review the code and apply secure coding practices.',
  };

  const severity = SEVERITY_MAP[issue.severity] || 'medium';
  const relativePath = issue.filename
    ? path.relative(targetDir, issue.filename)
    : 'Unknown';

  return {
    id: `MYTH-${String(vulnId).padStart(3, '0')}`,
    title: swcInfo.name,
    severity,
    threatId: '',
    description: issue.description || `${issue.swcTitle} detected`,
    filePath: relativePath,
    lineNumber: issue.lineno || 0,
    codeSnippet: issue.code || '',
    exploitability: issue.tx_sequence
      ? `Attack sequence: ${issue.tx_sequence}`
      : `Detected at address ${issue.address}`,
    remediation: swcInfo.remediation,
    aiFixPrompt: `Fix the ${swcInfo.name} vulnerability (${issue.swcID}) in ${relativePath}:${issue.lineno}. ${swcInfo.remediation}`,
    contractName: issue.contract || 'Unknown',
    functionName: issue.function || undefined,
    detector: issue.swcID,
    tool: 'mythril',
  };
}

/**
 * Get list of SWC IDs that Mythril detects
 */
export function getMythrilDetectors(): string[] {
  return Object.keys(SWC_INFO);
}
