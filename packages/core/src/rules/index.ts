/**
 * Security Rules Loader
 * Loads and manages security rules for the scanner
 */

import * as fs from 'fs';
import * as path from 'path';

export interface SecurityRule {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  patterns: string[];
  cwe: string | null;
  enabled: boolean;
  fix: string;
  arcSpecific?: boolean;
}

export interface RuleSet {
  name: string;
  version: string;
  description?: string;
  rules: SecurityRule[];
}

// Get rules directory - resolve from the package root
function getRulesDir(): string {
  // Try to find the rules directory relative to this file
  // In compiled dist, it's at dist/rules, and JSON files are in src/rules
  const possiblePaths = [
    path.join(__dirname, '..', 'src', 'rules'),  // from dist/rules -> src/rules
    path.join(__dirname),                         // same directory
    path.join(__dirname, '..', 'rules'),          // up one then rules
    path.resolve(__dirname, '..', '..', 'src', 'rules'), // from dist -> src/rules
  ];

  for (const p of possiblePaths) {
    const testFile = path.join(p, 'solidity-rules.json');
    if (fs.existsSync(testFile)) {
      return p;
    }
  }

  // Default to __dirname
  return __dirname;
}

const RULES_DIR = getRulesDir();

// Load a rule file
function loadRuleFile(filename: string): RuleSet | null {
  try {
    const filePath = path.join(RULES_DIR, filename);
    if (!fs.existsSync(filePath)) {
      return null;
    }
    const content = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    // Silently fail for missing rule files
    return null;
  }
}

// All available rule sets
const RULE_FILES = [
  'solidity-rules.json',
  'owasp-rules.json',
  'arc-rules.json',
  'web-rules.json',
  'genlayer-rules.json',
];

// Load all rules
export function loadAllRules(): SecurityRule[] {
  const allRules: SecurityRule[] = [];

  for (const file of RULE_FILES) {
    const ruleSet = loadRuleFile(file);
    if (ruleSet) {
      allRules.push(...ruleSet.rules.filter(r => r.enabled));
    }
  }

  return allRules;
}

// Load rules by category
export function loadRulesByCategory(category: string): SecurityRule[] {
  return loadAllRules().filter(rule => rule.category === category);
}

// Load rules by severity
export function loadRulesBySeverity(severity: string): SecurityRule[] {
  return loadAllRules().filter(rule => rule.severity === severity);
}

// Load only Arc-specific rules
export function loadArcRules(): SecurityRule[] {
  return loadAllRules().filter(rule => rule.arcSpecific === true);
}

// Load rules for smart contracts
export function loadSmartContractRules(): SecurityRule[] {
  const ruleSet = loadRuleFile('solidity-rules.json');
  const arcRuleSet = loadRuleFile('arc-rules.json');

  const rules: SecurityRule[] = [];
  if (ruleSet) rules.push(...ruleSet.rules.filter(r => r.enabled));
  if (arcRuleSet) rules.push(...arcRuleSet.rules.filter(r => r.enabled));

  return rules;
}

// Load rules for web applications
export function loadWebRules(): SecurityRule[] {
  const owaspRuleSet = loadRuleFile('owasp-rules.json');
  const webRuleSet = loadRuleFile('web-rules.json');

  const rules: SecurityRule[] = [];
  if (owaspRuleSet) rules.push(...owaspRuleSet.rules.filter(r => r.enabled));
  if (webRuleSet) rules.push(...webRuleSet.rules.filter(r => r.enabled));

  return rules;
}

// Match code against rules using patterns
export function matchRules(code: string, rules: SecurityRule[]): Array<{
  rule: SecurityRule;
  matches: RegExpMatchArray[];
  lines: number[];
}> {
  const findings: Array<{
    rule: SecurityRule;
    matches: RegExpMatchArray[];
    lines: number[];
  }> = [];

  const lines = code.split('\n');

  for (const rule of rules) {
    const ruleMatches: RegExpMatchArray[] = [];
    const matchedLines: number[] = [];

    for (const pattern of rule.patterns) {
      try {
        const regex = new RegExp(pattern, 'gi');

        // Check each line
        lines.forEach((line, index) => {
          const match = line.match(regex);
          if (match) {
            ruleMatches.push(match);
            if (!matchedLines.includes(index + 1)) {
              matchedLines.push(index + 1);
            }
          }
        });
      } catch {
        // Invalid regex pattern, skip
      }
    }

    if (ruleMatches.length > 0) {
      findings.push({
        rule,
        matches: ruleMatches,
        lines: matchedLines.sort((a, b) => a - b),
      });
    }
  }

  return findings;
}

// Get rule statistics
export function getRuleStats(): {
  total: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
} {
  const rules = loadAllRules();

  const bySeverity: Record<string, number> = {};
  const byCategory: Record<string, number> = {};

  for (const rule of rules) {
    bySeverity[rule.severity] = (bySeverity[rule.severity] || 0) + 1;
    byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
  }

  return {
    total: rules.length,
    bySeverity,
    byCategory,
  };
}

// Format rules for AI prompt
export function formatRulesForPrompt(rules: SecurityRule[]): string {
  const grouped: Record<string, SecurityRule[]> = {};

  for (const rule of rules) {
    if (!grouped[rule.category]) {
      grouped[rule.category] = [];
    }
    grouped[rule.category].push(rule);
  }

  let prompt = '## Security Rules to Check\n\n';

  for (const [category, categoryRules] of Object.entries(grouped)) {
    prompt += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n`;

    for (const rule of categoryRules) {
      prompt += `- **${rule.id}** [${rule.severity.toUpperCase()}]: ${rule.name}\n`;
      prompt += `  - ${rule.description}\n`;
      if (rule.cwe) {
        prompt += `  - CWE: ${rule.cwe}\n`;
      }
    }
    prompt += '\n';
  }

  return prompt;
}
