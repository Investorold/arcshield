export * from "./types.js";
export * from "./engine.js";

// Backward compatibility exports for code-review agent
import type { Rule, RuleSeverity } from './types.js';

export interface SecurityRule {
  id: string;
  name: string;
  severity: RuleSeverity;
  description: string;
  pattern?: string;
  patterns?: string[];
  detection?: string;
  recommendation?: string;
  fix?: string;
  cweId?: string;
  cwe?: string | null;
}

// Convert new Rule format to legacy SecurityRule format
function ruleToSecurityRule(rule: Rule): SecurityRule {
  return {
    id: rule.id,
    name: rule.name,
    severity: rule.severity,
    description: rule.description,
    patterns: rule.patterns.map(p => p.pattern),
    recommendation: rule.remediation,
    fix: rule.remediation,
    cweId: rule.cwe,
    cwe: rule.cwe || null,
  };
}

// Legacy functions for backward compatibility
export function loadAllRules(): SecurityRule[] {
  // Return empty array - the RuleEngine is now the primary scanner
  // These functions are kept for API compatibility
  return [];
}

export function loadSmartContractRules(): SecurityRule[] {
  return [];
}

export function loadWebRules(): SecurityRule[] {
  return [];
}

export function formatRulesForPrompt(rules: SecurityRule[]): string {
  if (rules.length === 0) {
    return 'No specific rules loaded - using AI-based analysis.';
  }
  return rules.map(r => `- ${r.id}: ${r.name} (${r.severity})`).join('\n');
}
