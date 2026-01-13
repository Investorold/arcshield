/**
 * Third-Party Code Detection
 *
 * Follows OWASP Vulnerable Dependency Management guidelines and
 * NIST SBOM (Software Bill of Materials) best practices for
 * distinguishing first-party code from third-party dependencies.
 *
 * Key standards implemented:
 * - OWASP Top 10:2025 A06 - Vulnerable and Outdated Components
 * - NIST SP 800-161 - Supply Chain Risk Management
 * - NTIA SBOM Minimum Elements
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
 * @see https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-software-1
 */

// Re-export DependencyType from types for convenience
import type { DependencyType } from '../types/index.js';
export type { DependencyType };

// Common third-party directory patterns
const THIRD_PARTY_DIRS = [
  'node_modules',
  'vendor',
  'bower_components',
  'jspm_packages',
  'third_party',
  'third-party',
  'external',
  'deps',
  'lib/vendor',
  'assets/vendor',
  'public/vendor',
  'static/vendor',
  '.pnpm',           // pnpm package store
  '.yarn/cache',     // yarn 2+ cache
  'go/pkg/mod',      // Go modules
  'target/dependency', // Maven/Gradle
  'Pods',            // CocoaPods (iOS)
  'Carthage',        // Carthage (iOS)
];

// SDK and bundled library patterns
const SDK_PATTERNS = [
  /[-_]sdk[-_.]/, // matches *-sdk-*, *_sdk.*, etc.
  /[-_]lib[-_.]/, // matches *-lib-*, *_lib.*, etc.
  /\.bundle\./, // bundled files
  /\.bundled\./, // bundled files
  /\.vendor\./, // vendor files
  /\.min\.js$/, // minified JS (often third-party)
  /\.min\.css$/, // minified CSS
  /\.packed\./, // packed files
  /relayer-sdk/, // Zama relayer SDK
  /fhevm/, // FHEVM SDK
  /ethers\./, // ethers.js
  /web3\./, // web3.js
  /wasm/, // WebAssembly (usually compiled libs)
];

// Test file patterns (not third-party but should be flagged differently)
const TEST_PATTERNS = [
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\/__tests__\//,
  /\/test\//,
  /\/tests\//,
  /\/testing\//,
  /\.stories\.[jt]sx?$/, // Storybook
  /\/fixtures\//,
  /\/mocks\//,
  /\/e2e\//,
  /codegen/, // generated test code
];

// Build/generated file patterns
const GENERATED_PATTERNS = [
  /\/dist\//,
  /\/build\//,
  /\/out\//,
  /\.generated\./,
  /\.g\.[jt]s$/,
  /\.d\.ts$/, // TypeScript declaration files
  /\/coverage\//,
  /\.cache\//,
];

/**
 * Result of third-party detection analysis
 * Aligned with SBOM component classification standards
 */
export interface ThirdPartyResult {
  isThirdParty: boolean;
  source?: string;
  dependencyType?: DependencyType;
  isTest?: boolean;
  isGenerated?: boolean;
  // VEX-style status for vulnerability relevance
  // @see https://www.cisa.gov/sbom
  exploitabilityStatus?: 'affected' | 'not_affected' | 'under_investigation' | 'fixed';
}

/**
 * Detect if a file path belongs to third-party code
 * Implements OWASP guidance for distinguishing direct vs transitive dependencies
 */
export function detectThirdParty(filePath: string): ThirdPartyResult {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

  // Check for third-party directories
  for (const dir of THIRD_PARTY_DIRS) {
    if (normalizedPath.includes(`/${dir}/`) || normalizedPath.startsWith(`${dir}/`)) {
      // Determine dependency type based on path depth
      const dependencyType = determineDependencyType(normalizedPath, dir);
      return {
        isThirdParty: true,
        source: dir,
        dependencyType,
        // Default to 'under_investigation' - needs reachability analysis
        exploitabilityStatus: 'under_investigation',
      };
    }
  }

  // Check for SDK patterns (usually bundled/vendored)
  for (const pattern of SDK_PATTERNS) {
    if (pattern.test(normalizedPath)) {
      const match = normalizedPath.match(pattern);
      return {
        isThirdParty: true,
        source: match ? match[0].replace(/[-_.]/g, '') : 'sdk',
        dependencyType: 'bundled',
        exploitabilityStatus: 'under_investigation',
      };
    }
  }

  // Check for test files (not third-party but flagged)
  for (const pattern of TEST_PATTERNS) {
    if (pattern.test(normalizedPath)) {
      return { isThirdParty: false, isTest: true };
    }
  }

  // Check for generated files
  for (const pattern of GENERATED_PATTERNS) {
    if (pattern.test(normalizedPath)) {
      return { isThirdParty: false, isGenerated: true };
    }
  }

  return { isThirdParty: false };
}

/**
 * Determine if dependency is direct or transitive based on path structure
 * Per OWASP: "Acting on transitive dependencies risks application instability"
 */
function determineDependencyType(path: string, source: string): DependencyType {
  // Vendored code (copied into project)
  if (source === 'vendor' || source.includes('vendor')) {
    return 'vendored';
  }

  // Check for nested node_modules (transitive dependency)
  const nodeModulesCount = (path.match(/node_modules/g) || []).length;
  if (nodeModulesCount > 1) {
    return 'transitive';
  }

  // Check for pnpm/yarn nested structures
  if (path.includes('.pnpm') || path.includes('.yarn')) {
    return 'transitive';
  }

  return 'direct';
}

/**
 * Check if content looks like minified/bundled code
 * (Long lines, few newlines, obfuscated variable names)
 */
export function looksLikeMinifiedCode(content: string): boolean {
  if (!content || content.length < 1000) return false;

  const lines = content.split('\n');

  // Check for very long lines (typical of minified code)
  const hasVeryLongLines = lines.some(line => line.length > 500);

  // Check for low line count relative to content length
  const avgLineLength = content.length / lines.length;
  const hasHighAvgLineLength = avgLineLength > 200;

  // Check for typical minification patterns
  const hasMinificationPatterns = /[a-z]\.[a-z]\.[a-z]\(/.test(content) || // a.b.c(
    /\}\)\(/.test(content) || // })( IIFE pattern
    /,function\(/.test(content); // ,function( consecutive functions

  return hasVeryLongLines || (hasHighAvgLineLength && hasMinificationPatterns);
}

/**
 * Tag vulnerabilities with third-party information
 * Follows OWASP guidance for dependency vulnerability classification
 */
export function tagVulnerabilities<T extends {
  filePath: string;
  severity?: string;
  isThirdParty?: boolean;
  thirdPartySource?: string;
  dependencyType?: DependencyType;
}>(
  vulnerabilities: T[]
): T[] {
  return vulnerabilities.map(vuln => {
    const result = detectThirdParty(vuln.filePath);
    return {
      ...vuln,
      isThirdParty: result.isThirdParty,
      thirdPartySource: result.source,
      dependencyType: result.dependencyType,
    };
  });
}

/**
 * Calculate priority score for vulnerability triage
 * Based on industry best practices from Snyk, Sonatype, and OWASP
 *
 * Score factors:
 * - Severity (CVSS-aligned)
 * - First-party vs third-party (your code is higher priority)
 * - Direct vs transitive dependency
 * - Exploitability indicators
 *
 * @returns Priority score 0-100 (higher = more urgent)
 */
export function calculatePriorityScore(vuln: {
  severity: string;
  isThirdParty?: boolean;
  dependencyType?: DependencyType;
  isTest?: boolean;
}): number {
  let score = 0;

  // Base severity score (aligned with CVSS v3)
  switch (vuln.severity) {
    case 'critical': score = 90; break;
    case 'high': score = 70; break;
    case 'medium': score = 50; break;
    case 'low': score = 30; break;
    case 'info': score = 10; break;
    default: score = 25;
  }

  // First-party code gets +10 priority (you control it)
  if (!vuln.isThirdParty) {
    score += 10;
  } else {
    // Third-party: direct dependencies are higher priority than transitive
    // Per OWASP: "Acting on transitive dependencies risks application instability"
    if (vuln.dependencyType === 'direct') {
      score += 5;
    } else if (vuln.dependencyType === 'transitive') {
      score -= 10; // Lower priority - harder to fix directly
    } else if (vuln.dependencyType === 'vendored') {
      score += 3; // Vendored = you copied it, you should fix it
    }
  }

  // Test code is lower priority (not in production)
  if (vuln.isTest) {
    score -= 15;
  }

  // Clamp to 0-100
  return Math.max(0, Math.min(100, score));
}

/**
 * Split vulnerabilities into first-party and third-party
 */
export function splitVulnerabilities<T extends { isThirdParty?: boolean }>(
  vulnerabilities: T[]
): { firstParty: T[]; thirdParty: T[] } {
  const firstParty: T[] = [];
  const thirdParty: T[] = [];

  for (const vuln of vulnerabilities) {
    if (vuln.isThirdParty) {
      thirdParty.push(vuln);
    } else {
      firstParty.push(vuln);
    }
  }

  return { firstParty, thirdParty };
}

/**
 * Calculate summary for a list of vulnerabilities
 */
export function calculateSummary<T extends { severity: string }>(
  vulnerabilities: T[]
): { totalIssues: number; critical: number; high: number; medium: number; low: number; info: number } {
  return {
    totalIssues: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  };
}
