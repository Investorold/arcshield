/**
 * Rule Engine
 *
 * Loads rules from JSON files and executes pattern matching against code.
 */

import * as fs from 'fs';
import * as path from 'path';
import type {
  Rule,
  RuleSet,
  RuleMatch,
  RuleEngineConfig,
  RuleSeverity,
  RuleCategory,
  RuleLanguage,
  RuleFramework,
} from './types.js';
import type { FileContext, Vulnerability, Severity } from '../types/index.js';

const DEFAULT_RULE_DIRS = [
  path.join(__dirname, 'builtin'),
  path.join(__dirname, 'custom'),
];

export class RuleEngine {
  private rules: Rule[] = [];
  private config: RuleEngineConfig;
  private loadedRuleSets: Map<string, RuleSet> = new Map();

  constructor(config?: Partial<RuleEngineConfig>) {
    this.config = {
      ruleDirs: config?.ruleDirs || DEFAULT_RULE_DIRS,
      enableRules: config?.enableRules,
      disableRules: config?.disableRules,
      severityFilter: config?.severityFilter,
      categoryFilter: config?.categoryFilter,
      languageFilter: config?.languageFilter,
      frameworkFilter: config?.frameworkFilter,
    };
  }

  /**
   * Load all rules from configured directories
   */
  async loadRules(): Promise<void> {
    this.rules = [];
    this.loadedRuleSets.clear();

    for (const dir of this.config.ruleDirs) {
      if (!fs.existsSync(dir)) {
        continue;
      }

      const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));

      for (const file of files) {
        try {
          const filePath = path.join(dir, file);
          const content = fs.readFileSync(filePath, 'utf-8');
          const ruleSet: RuleSet = JSON.parse(content);

          this.loadedRuleSets.set(ruleSet.name, ruleSet);

          // Filter and add rules
          for (const rule of ruleSet.rules) {
            if (this.shouldIncludeRule(rule)) {
              this.rules.push(rule);
            }
          }

          console.log(`[RuleEngine] Loaded ${ruleSet.rules.length} rules from ${file}`);
        } catch (error) {
          console.error(`[RuleEngine] Error loading ${file}:`, error);
        }
      }
    }

    console.log(`[RuleEngine] Total rules loaded: ${this.rules.length}`);
  }

  /**
   * Check if a rule should be included based on config filters
   */
  private shouldIncludeRule(rule: Rule): boolean {
    // Check if explicitly disabled
    if (this.config.disableRules?.includes(rule.id)) {
      return false;
    }

    // If enableRules is set, only include those
    if (this.config.enableRules && !this.config.enableRules.includes(rule.id)) {
      return false;
    }

    // Check if rule is enabled by default
    if (!rule.enabled && !this.config.enableRules?.includes(rule.id)) {
      return false;
    }

    // Check severity filter
    if (this.config.severityFilter && !this.config.severityFilter.includes(rule.severity)) {
      return false;
    }

    // Check category filter
    if (this.config.categoryFilter && !this.config.categoryFilter.includes(rule.category)) {
      return false;
    }

    // Check language filter
    if (this.config.languageFilter) {
      const hasLanguage = rule.languages.some(
        lang => lang === 'any' || this.config.languageFilter!.includes(lang)
      );
      if (!hasLanguage) {
        return false;
      }
    }

    // Check framework filter
    if (this.config.frameworkFilter && rule.frameworks) {
      const hasFramework = rule.frameworks.some(
        fw => fw === 'any' || this.config.frameworkFilter!.includes(fw)
      );
      if (!hasFramework) {
        return false;
      }
    }

    return true;
  }

  /**
   * Scan files for rule violations
   */
  scan(files: FileContext[]): RuleMatch[] {
    const matches: RuleMatch[] = [];

    for (const file of files) {
      const language = this.getLanguageFromFile(file.path);
      const framework = this.detectFramework(file.content);

      // Get applicable rules for this file
      const applicableRules = this.rules.filter(rule => {
        const languageMatch = rule.languages.includes('any') ||
          rule.languages.includes(language as RuleLanguage);

        const frameworkMatch = !rule.frameworks ||
          rule.frameworks.includes('any') ||
          (framework && rule.frameworks.includes(framework));

        return languageMatch && frameworkMatch;
      });

      // Run each rule against the file
      for (const rule of applicableRules) {
        const ruleMatches = this.scanFileWithRule(file, rule);
        matches.push(...ruleMatches);
      }
    }

    return matches;
  }

  /**
   * Scan a single file with a single rule
   */
  private scanFileWithRule(file: FileContext, rule: Rule): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const lines = file.content.split('\n');

    // Check each pattern
    for (const patternDef of rule.patterns) {
      try {
        const flags = patternDef.flags || 'gi';
        const regex = new RegExp(patternDef.pattern, flags);

        if (patternDef.multiline) {
          // Multi-line pattern matching - add 'm' flag if not already present
          const multilineFlags = flags.includes('m') ? flags : flags + 'm';
          const multiMatches = file.content.matchAll(new RegExp(patternDef.pattern, multilineFlags));
          for (const match of multiMatches) {
            if (match.index !== undefined) {
              // Calculate line number from index
              const lineNumber = file.content.substring(0, match.index).split('\n').length;

              // Check exclude patterns
              if (this.matchesExcludePattern(file.content, rule, lineNumber)) {
                continue;
              }

              matches.push({
                rule,
                filePath: file.path,
                lineNumber,
                codeSnippet: match[0].substring(0, 200),
                matchedPattern: patternDef.pattern,
              });
            }
          }
        } else {
          // Line-by-line matching
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            regex.lastIndex = 0; // Reset for global flag

            if (regex.test(line)) {
              const lineNumber = i + 1;

              // Check exclude patterns
              if (this.matchesExcludePattern(file.content, rule, lineNumber, lines)) {
                continue;
              }

              matches.push({
                rule,
                filePath: file.path,
                lineNumber,
                codeSnippet: line.trim(),
                matchedPattern: patternDef.pattern,
              });
            }
          }
        }
      } catch (error) {
        console.error(`[RuleEngine] Invalid pattern in rule ${rule.id}:`, error);
      }
    }

    return matches;
  }

  /**
   * Check if line matches any exclude patterns
   */
  private matchesExcludePattern(
    content: string,
    rule: Rule,
    lineNumber: number,
    lines?: string[]
  ): boolean {
    if (!rule.excludePatterns) {
      return false;
    }

    const allLines = lines || content.split('\n');
    const contextStart = Math.max(0, lineNumber - 10);
    const contextEnd = Math.min(allLines.length, lineNumber + 5);
    const context = allLines.slice(contextStart, contextEnd).join('\n');

    for (const excludePattern of rule.excludePatterns) {
      try {
        const regex = new RegExp(excludePattern.pattern, excludePattern.flags || 'gi');
        if (regex.test(context)) {
          return true;
        }
      } catch {
        // Invalid pattern, skip
      }
    }

    return false;
  }

  /**
   * Convert rule matches to vulnerability format
   */
  toVulnerabilities(matches: RuleMatch[]): Vulnerability[] {
    const vulnMap = new Map<string, Vulnerability>();

    for (const match of matches) {
      // Deduplicate by file+line+rule
      const key = `${match.filePath}:${match.lineNumber}:${match.rule.id}`;

      if (!vulnMap.has(key)) {
        const confidenceText = match.rule.confidence === 'high' ? 'High' :
                              match.rule.confidence === 'medium' ? 'Medium' : 'Low';
        vulnMap.set(key, {
          id: `${match.rule.id}-${String(vulnMap.size + 1).padStart(3, '0')}`,
          title: match.rule.name,
          severity: match.rule.severity as Severity,
          threatId: '', // Rule-based findings may not be linked to specific threats
          description: match.rule.description,
          filePath: match.filePath,
          lineNumber: match.lineNumber,
          codeSnippet: match.codeSnippet,
          cweId: match.rule.cwe,
          exploitability: `${confidenceText} - Pattern-based detection via rule ${match.rule.id}`,
          remediation: match.rule.remediation,
          aiFixPrompt: `Fix the ${match.rule.name} vulnerability at ${match.filePath}:${match.lineNumber}. ${match.rule.remediation}`,
        });
      }
    }

    return Array.from(vulnMap.values());
  }

  /**
   * Get language from file extension
   */
  private getLanguageFromFile(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const langMap: Record<string, RuleLanguage> = {
      '.js': 'javascript',
      '.jsx': 'javascript',
      '.ts': 'typescript',
      '.tsx': 'typescript',
      '.py': 'python',
      '.sol': 'solidity',
      '.rs': 'rust',
      '.go': 'go',
      '.java': 'java',
    };
    return langMap[ext] || 'any';
  }

  /**
   * Detect framework from file content
   */
  private detectFramework(content: string): RuleFramework | null {
    if (content.includes('from genlayer') || content.includes('gl.Contract')) {
      return 'genlayer';
    }
    if (content.includes('import React') || content.includes('from "react"')) {
      return 'react';
    }
    if (content.includes('express()') || content.includes('from "express"')) {
      return 'express';
    }
    if (content.includes('from django') || content.includes('import django')) {
      return 'django';
    }
    if (content.includes('from flask') || content.includes('import flask')) {
      return 'flask';
    }
    if (content.includes('pragma solidity')) {
      return 'hardhat'; // Default for Solidity
    }
    return null;
  }

  /**
   * Get all loaded rules
   */
  getRules(): Rule[] {
    return [...this.rules];
  }

  /**
   * Get loaded rule sets
   */
  getRuleSets(): RuleSet[] {
    return Array.from(this.loadedRuleSets.values());
  }

  /**
   * Get rule by ID
   */
  getRule(id: string): Rule | undefined {
    return this.rules.find(r => r.id === id);
  }

  /**
   * Get rules by category
   */
  getRulesByCategory(category: RuleCategory): Rule[] {
    return this.rules.filter(r => r.category === category);
  }

  /**
   * Get rules by severity
   */
  getRulesBySeverity(severity: RuleSeverity): Rule[] {
    return this.rules.filter(r => r.severity === severity);
  }

  /**
   * Add a custom rule at runtime
   */
  addRule(rule: Rule): void {
    if (this.shouldIncludeRule(rule)) {
      this.rules.push(rule);
    }
  }

  /**
   * Remove a rule by ID
   */
  removeRule(id: string): boolean {
    const index = this.rules.findIndex(r => r.id === id);
    if (index >= 0) {
      this.rules.splice(index, 1);
      return true;
    }
    return false;
  }

  /**
   * Enable a rule by ID
   */
  enableRule(id: string): boolean {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      rule.enabled = true;
      return true;
    }
    return false;
  }

  /**
   * Disable a rule by ID
   */
  disableRule(id: string): boolean {
    const rule = this.rules.find(r => r.id === id);
    if (rule) {
      rule.enabled = false;
      return true;
    }
    return false;
  }

  /**
   * Get statistics about loaded rules
   */
  getStats(): {
    total: number;
    byCategory: Record<string, number>;
    bySeverity: Record<string, number>;
    byLanguage: Record<string, number>;
  } {
    const stats = {
      total: this.rules.length,
      byCategory: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      byLanguage: {} as Record<string, number>,
    };

    for (const rule of this.rules) {
      stats.byCategory[rule.category] = (stats.byCategory[rule.category] || 0) + 1;
      stats.bySeverity[rule.severity] = (stats.bySeverity[rule.severity] || 0) + 1;
      for (const lang of rule.languages) {
        stats.byLanguage[lang] = (stats.byLanguage[lang] || 0) + 1;
      }
    }

    return stats;
  }
}

// Export singleton instance
let defaultEngine: RuleEngine | null = null;

export function getDefaultRuleEngine(): RuleEngine {
  if (!defaultEngine) {
    defaultEngine = new RuleEngine();
  }
  return defaultEngine;
}

export async function initializeRuleEngine(config?: Partial<RuleEngineConfig>): Promise<RuleEngine> {
  const engine = new RuleEngine(config);
  await engine.loadRules();
  return engine;
}
