/**
 * Rule System Types
 *
 * Defines the schema for extensible security rules
 */

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RuleCategory =
  | 'injection'           // SQL, Command, Prompt injection
  | 'authentication'      // Auth bypass, weak auth
  | 'authorization'       // Access control issues
  | 'cryptography'        // Weak crypto, hardcoded secrets
  | 'data_exposure'       // Information disclosure
  | 'input_validation'    // Missing or weak validation
  | 'configuration'       // Security misconfigurations
  | 'smart_contract'      // Blockchain-specific
  | 'prompt_injection'    // LLM/AI specific
  | 'api_security'        // API vulnerabilities
  | 'dos'                 // Denial of service
  | 'other';

export type RuleLanguage =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'solidity'
  | 'rust'
  | 'go'
  | 'java'
  | 'any';               // Language-agnostic rules

export type RuleFramework =
  | 'genlayer'
  | 'react'
  | 'express'
  | 'django'
  | 'flask'
  | 'hardhat'
  | 'foundry'
  | 'any';

export interface RulePattern {
  /** Regex pattern to match */
  pattern: string;
  /** Pattern flags (g, i, m, etc.) */
  flags?: string;
  /** Whether pattern is multiline */
  multiline?: boolean;
  /** Description of what this pattern catches */
  description?: string;
}

export interface Rule {
  /** Unique rule identifier (e.g., "GL001", "OWASP-A01-001") */
  id: string;

  /** Human-readable rule name */
  name: string;

  /** Detailed description of the vulnerability */
  description: string;

  /** Severity level */
  severity: RuleSeverity;

  /** Category for grouping */
  category: RuleCategory;

  /** Languages this rule applies to */
  languages: RuleLanguage[];

  /** Frameworks this rule applies to (optional) */
  frameworks?: RuleFramework[];

  /** Patterns to detect the vulnerability */
  patterns: RulePattern[];

  /** Patterns that indicate safe code (skip if matched) */
  excludePatterns?: RulePattern[];

  /** CWE ID if applicable */
  cwe?: string;

  /** OWASP category if applicable */
  owasp?: string;

  /** How to fix this vulnerability */
  remediation: string;

  /** Example of vulnerable code */
  badExample?: string;

  /** Example of fixed code */
  goodExample?: string;

  /** Is this rule enabled by default */
  enabled: boolean;

  /** Tags for filtering */
  tags?: string[];

  /** Confidence level (high = fewer false positives) */
  confidence?: 'high' | 'medium' | 'low';
}

export interface RuleSet {
  /** Name of the ruleset */
  name: string;

  /** Version of the ruleset */
  version: string;

  /** Description */
  description: string;

  /** Author/maintainer */
  author?: string;

  /** URL for more info */
  url?: string;

  /** The rules in this set */
  rules: Rule[];
}

export interface RuleMatch {
  /** The rule that matched */
  rule: Rule;

  /** File where match was found */
  filePath: string;

  /** Line number of match */
  lineNumber: number;

  /** The matching code snippet */
  codeSnippet: string;

  /** Which pattern matched */
  matchedPattern: string;
}

export interface RuleEngineConfig {
  /** Directories to load rules from */
  ruleDirs: string[];

  /** Specific rule IDs to enable (overrides defaults) */
  enableRules?: string[];

  /** Specific rule IDs to disable */
  disableRules?: string[];

  /** Only run rules of these severities */
  severityFilter?: RuleSeverity[];

  /** Only run rules of these categories */
  categoryFilter?: RuleCategory[];

  /** Only run rules for these languages */
  languageFilter?: RuleLanguage[];

  /** Only run rules for these frameworks */
  frameworkFilter?: RuleFramework[];
}
