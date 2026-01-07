/**
 * Arc-Specific Security Scanner
 *
 * Detects vulnerabilities specific to the Arc blockchain:
 * - block.prevrandao always returns 0
 * - USDC decimals (18 native vs 6 ERC-20)
 * - Instant finality (no confirmations needed)
 * - SELFDESTRUCT reverts in constructor
 * - Timestamp handling differences
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ArcVulnerability, Severity, FileContext } from '../types/index.js';

// Arc-specific vulnerability patterns
const ARC_RULES = [
  {
    id: 'ARC001',
    name: 'Unsafe block.prevrandao Usage',
    severity: 'high' as Severity,
    pattern: /block\.prevrandao|block\.difficulty/g,
    description: 'block.prevrandao always returns 0 on Arc. Using it for randomness is insecure.',
    recommendation: 'Use Chainlink VRF or another verifiable random function for randomness.',
    cweId: 'CWE-330',
  },
  {
    id: 'ARC002',
    name: 'Hardcoded 6-Decimal Assumption',
    severity: 'high' as Severity,
    pattern: /\b(1e6|10\s*\*\*\s*6|1000000)\b.*(?:decimals?|usdc|usdt|stable)/gi,
    description: 'Arc uses 18 decimals for native USDC, not 6. Hardcoding 6 decimals will cause calculation errors.',
    recommendation: 'Use 18 decimals (1e18) for USDC on Arc, or dynamically fetch decimals.',
    cweId: 'CWE-682',
  },
  {
    id: 'ARC003',
    name: 'Strict Timestamp Comparison',
    severity: 'medium' as Severity,
    pattern: /block\.timestamp\s*(==|!=)\s*/g,
    description: 'Multiple Arc blocks can share the same timestamp. Strict equality checks may fail.',
    recommendation: 'Use >= or <= for timestamp comparisons instead of strict equality.',
    cweId: 'CWE-697',
  },
  {
    id: 'ARC004',
    name: 'Unnecessary Confirmation Waits',
    severity: 'low' as Severity,
    pattern: /wait.*confirm|confirmation.*wait|require.*blocks?.*confirm/gi,
    description: 'Arc has instant deterministic finality. Waiting for confirmations is unnecessary.',
    recommendation: 'Remove confirmation wait logic - Arc transactions are final immediately.',
    cweId: 'CWE-400',
  },
  {
    id: 'ARC005',
    name: 'SELFDESTRUCT in Constructor',
    severity: 'high' as Severity,
    pattern: /constructor[^}]*selfdestruct/gis,
    description: 'SELFDESTRUCT reverts when called in constructor on Arc.',
    recommendation: 'Move selfdestruct logic to a separate function, not the constructor.',
    cweId: 'CWE-670',
  },
  {
    id: 'ARC006',
    name: 'Missing USDC Blocklist Handling',
    severity: 'medium' as Severity,
    pattern: /transfer\s*\([^)]*\)|transferFrom\s*\([^)]*\)/g,
    description: 'USDC has a blocklist. Transfers to/from blocked addresses will fail.',
    recommendation: 'Add try-catch or check blocklist status before USDC transfers.',
    cweId: 'CWE-754',
    additionalCheck: (content: string) => {
      // Only flag if dealing with USDC and no blocklist check
      const hasUsdc = /usdc/i.test(content);
      const hasBlocklistCheck = /blocklist|blocked|blacklist/i.test(content);
      return hasUsdc && !hasBlocklistCheck;
    },
  },
  {
    id: 'ARC007',
    name: 'Mixed Decimal Interface',
    severity: 'medium' as Severity,
    pattern: /\.decimals\s*\(\s*\)/g,
    description: 'When interacting with tokens, be aware Arc USDC has 18 decimals, not 6.',
    recommendation: 'Always use the decimals() function dynamically, never hardcode.',
    cweId: 'CWE-682',
    additionalCheck: (content: string) => {
      // Flag if there's hardcoded decimal logic nearby
      return /1e6|10\*\*6|1000000/.test(content);
    },
  },
];

/**
 * Scan Solidity files for Arc-specific vulnerabilities
 */
export async function runArcScanner(
  files: FileContext[]
): Promise<ArcVulnerability[]> {
  const vulnerabilities: ArcVulnerability[] = [];
  let vulnId = 1;

  // Filter to only Solidity files
  const solFiles = files.filter(f => f.path.endsWith('.sol'));

  if (solFiles.length === 0) {
    return vulnerabilities;
  }

  console.log(`[Arc Scanner] Analyzing ${solFiles.length} Solidity files...`);

  for (const file of solFiles) {
    const content = file.content;
    const lines = content.split('\n');

    for (const rule of ARC_RULES) {
      // Check additional conditions if any
      if (rule.additionalCheck && !rule.additionalCheck(content)) {
        continue;
      }

      // Find all matches
      let match: RegExpExecArray | null;
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);

      while ((match = regex.exec(content)) !== null) {
        // Find line number
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;

        // Get code snippet (the line and surrounding context)
        const startLine = Math.max(0, lineNumber - 2);
        const endLine = Math.min(lines.length - 1, lineNumber + 2);
        const codeSnippet = lines.slice(startLine, endLine + 1).join('\n');

        // Extract contract name from file
        const contractMatch = content.match(/contract\s+(\w+)/);
        const contractName = contractMatch ? contractMatch[1] : 'Unknown';

        // Extract function name if possible
        const beforeMatchContent = content.substring(0, match.index);
        const functionMatch = beforeMatchContent.match(/function\s+(\w+)[^{]*\{[^}]*$/);
        const functionName = functionMatch ? functionMatch[1] : undefined;

        vulnerabilities.push({
          id: `ARC-${String(vulnId++).padStart(3, '0')}`,
          title: rule.name,
          severity: rule.severity,
          threatId: '', // Will be linked later
          description: rule.description,
          filePath: file.path,
          lineNumber,
          codeSnippet,
          cweId: rule.cweId,
          exploitability: `Pattern match: ${match[0]}`,
          remediation: rule.recommendation,
          aiFixPrompt: `Fix the Arc-specific vulnerability "${rule.name}" at line ${lineNumber} in ${file.path}`,
          contractName,
          functionName,
          detector: rule.id,
          tool: 'arcshield',
          arcSpecific: true,
          arcRule: rule.id,
        });
      }
    }
  }

  console.log(`[Arc Scanner] Found ${vulnerabilities.length} Arc-specific issues`);
  return vulnerabilities;
}

/**
 * Get Arc-specific rule descriptions
 */
export function getArcRules(): typeof ARC_RULES {
  return ARC_RULES;
}
