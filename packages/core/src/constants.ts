/**
 * ArcShield Constants
 */

// Supported file extensions by language
export const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx'],
  solidity: ['.sol'],
  python: ['.py'],
  go: ['.go'],
  rust: ['.rs'],
  java: ['.java'],
  ruby: ['.rb'],
  php: ['.php'],
  csharp: ['.cs'],
  kotlin: ['.kt'],
  swift: ['.swift'],
  json: ['.json'],
  yaml: ['.yml', '.yaml'],
  markdown: ['.md'],
  html: ['.html', '.htm'],
  css: ['.css', '.scss', '.sass'],
};

// Files to always exclude from scanning
export const EXCLUDED_PATTERNS = [
  'node_modules/**',
  '.git/**',
  'dist/**',
  'build/**',
  'out/**',
  '.next/**',
  '.nuxt/**',
  'coverage/**',
  '*.min.js',
  '*.bundle.js',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '*.map',
];

// Sensitive file patterns to check
export const SENSITIVE_FILE_PATTERNS = [
  '.env',
  '.env.*',
  '*.pem',
  '*.key',
  '*secret*',
  '*credential*',
  '*password*',
  'config/secrets.*',
];

// STRIDE categories with descriptions
export const STRIDE_CATEGORIES = {
  spoofing: {
    name: 'Spoofing',
    description: 'Pretending to be something or someone other than yourself',
    examples: ['Authentication bypass', 'Session hijacking', 'Identity theft'],
  },
  tampering: {
    name: 'Tampering',
    description: 'Modifying data or code without authorization',
    examples: ['SQL injection', 'Cross-site scripting', 'Man-in-the-middle'],
  },
  repudiation: {
    name: 'Repudiation',
    description: 'Denying having performed an action',
    examples: ['Missing audit logs', 'Unsigned transactions', 'No accountability'],
  },
  information_disclosure: {
    name: 'Information Disclosure',
    description: 'Exposing information to unauthorized parties',
    examples: ['Data leakage', 'Error messages', 'Insecure storage'],
  },
  denial_of_service: {
    name: 'Denial of Service',
    description: 'Disrupting service availability',
    examples: ['Resource exhaustion', 'Infinite loops', 'Gas griefing'],
  },
  elevation_of_privilege: {
    name: 'Elevation of Privilege',
    description: 'Gaining unauthorized access or permissions',
    examples: ['Privilege escalation', 'Access control bypass', 'Admin takeover'],
  },
} as const;

// Severity levels with scores
export const SEVERITY_SCORES = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2,
  info: 0,
} as const;

// Badge eligibility threshold (score out of 100)
export const BADGE_THRESHOLD = 80;

// Arc-specific constants
export const ARC_CONSTANTS = {
  NATIVE_DECIMALS: 18,
  ERC20_DECIMALS: 6,
  PREV_RANDAO_VALUE: 0,
  FINALITY_TIME_MS: 350,
  RPC_TESTNET: 'https://rpc.testnet.arc.network',
} as const;

// Model costs (approximate per 1M tokens)
export const MODEL_COSTS = {
  haiku: { input: 0.25, output: 1.25 },
  sonnet: { input: 3, output: 15 },
  opus: { input: 15, output: 75 },
} as const;

// CWE mappings for common vulnerabilities
export const CWE_MAPPINGS: Record<string, { id: string; name: string }> = {
  sql_injection: { id: 'CWE-89', name: 'SQL Injection' },
  xss: { id: 'CWE-79', name: 'Cross-site Scripting' },
  hardcoded_secret: { id: 'CWE-798', name: 'Hardcoded Credentials' },
  weak_crypto: { id: 'CWE-327', name: 'Broken Cryptographic Algorithm' },
  reentrancy: { id: 'CWE-841', name: 'Reentrancy' },
  integer_overflow: { id: 'CWE-190', name: 'Integer Overflow' },
  access_control: { id: 'CWE-284', name: 'Improper Access Control' },
  path_traversal: { id: 'CWE-22', name: 'Path Traversal' },
  command_injection: { id: 'CWE-78', name: 'OS Command Injection' },
  insecure_random: { id: 'CWE-330', name: 'Insufficient Random Values' },
};
