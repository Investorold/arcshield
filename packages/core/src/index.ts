/**
 * ArcShield Core
 * Multi-Agent AI Security Scanner for Arc Ecosystem
 */

import * as fs from 'fs';
import * as path from 'path';
import type { ScanConfig, ScanReport, AgentContext } from './types/index.js';
import { walkFiles } from './utils/file-walker.js';
import { AssessmentAgent } from './agents/assessment.js';
import { ThreatModelingAgent } from './agents/threat-modeling.js';
import { CodeReviewAgent } from './agents/code-review.js';
import { ReportGeneratorAgent } from './agents/report-generator.js';
import { runSlither, isSlitherInstalled } from './scanners/slither.js';
import { runMythril, isMythrilInstalled } from './scanners/mythril.js';
import { runArcScanner } from './scanners/arc-scanner.js';
import { runGenLayerScanner, hasGenLayerContracts } from './scanners/genlayer/index.js';
import { BADGE_THRESHOLD } from './constants.js';
import { RuleEngine, initializeRuleEngine } from './rules/engine.js';
import type { RuleEngineConfig, Rule, RuleSet } from './rules/types.js';
import {
  tagVulnerabilities,
  splitVulnerabilities,
  calculateSummary,
  calculatePriorityScore,
} from './utils/third-party-detector.js';

// Export types
export * from './types/index.js';

// Export constants
export * from './constants.js';

// Export utilities
export * from './utils/index.js';

// Export agents
export * from './agents/index.js';

// Export scanners
export * from './scanners/index.js';

// Export rules system
export * from './rules/index.js';

// Version
export const VERSION = '0.1.0';

// Extended scan config with rule engine support
export interface ExtendedScanConfig extends ScanConfig {
  ruleEngineConfig?: Partial<RuleEngineConfig>;
  enableRuleEngine?: boolean;
}

// Main Scanner class
export class Scanner {
  private config: ExtendedScanConfig;
  private ruleEngine: RuleEngine | null = null;

  constructor(config: Partial<ExtendedScanConfig> = {}) {
    this.config = {
      target: config.target || '.',
      targetType: config.targetType || 'local',
      includeSmartContracts: config.includeSmartContracts ?? true,
      includeWebApp: config.includeWebApp ?? true,
      includeGenLayer: config.includeGenLayer ?? false,
      provider: config.provider || 'anthropic',
      model: config.model || 'sonnet',
      ollamaUrl: config.ollamaUrl || 'http://localhost:11434',
      outputFormat: config.outputFormat || 'json',
      outputPath: config.outputPath,
      enableRuleEngine: config.enableRuleEngine ?? true,
      ruleEngineConfig: config.ruleEngineConfig,
    };
  }

  /**
   * Get the rule engine (initializes if needed)
   */
  async getRuleEngine(): Promise<RuleEngine> {
    if (!this.ruleEngine) {
      this.ruleEngine = await initializeRuleEngine(this.config.ruleEngineConfig);
    }
    return this.ruleEngine;
  }

  /**
   * Get available rules
   */
  async getRules(): Promise<Rule[]> {
    const engine = await this.getRuleEngine();
    return engine.getRules();
  }

  /**
   * Get available rule sets
   */
  async getRuleSets(): Promise<RuleSet[]> {
    const engine = await this.getRuleEngine();
    return engine.getRuleSets();
  }

  /**
   * Run a full security scan
   */
  async scan(): Promise<ScanReport> {
    const startTime = Date.now();
    let totalCost = 0;

    console.log('\n🛡️  ArcShield Security Scanner');
    console.log('━'.repeat(50));

    // Step 1: Discover files
    console.log('\n📂 Discovering files...');
    const workDir = path.resolve(this.config.target);
    const files = await walkFiles({ rootDir: workDir });
    console.log(`   Found ${files.length} files to analyze`);

    // Create agent context
    const context: AgentContext = {
      workDir,
      files,
      config: this.config,
      previousResults: {},
    };

    // Show provider info
    const providerInfo = this.config.provider === 'ollama'
      ? `Ollama (${this.config.model})`
      : `Claude ${this.config.model}`;
    console.log(`   Using: ${providerInfo}`);

    // Step 1.5: Run Rule Engine (pattern-based scanning)
    let ruleBasedVulns: ScanReport['vulnerabilities']['vulnerabilities'] = [];
    if (this.config.enableRuleEngine) {
      console.log('\n📋 Running Rule-Based Scanner...');
      const engine = await this.getRuleEngine();
      const stats = engine.getStats();
      console.log(`   Loaded ${stats.total} rules across ${Object.keys(stats.byCategory).length} categories`);

      const matches = engine.scan(files);
      ruleBasedVulns = engine.toVulnerabilities(matches);
      console.log(`   Found ${ruleBasedVulns.length} issues via pattern matching`);
    }

    // Step 2: Run Assessment Agent
    console.log('\n🔍 Phase 1: Assessment');
    const assessmentAgent = new AssessmentAgent(
      this.config.model,
      this.config.provider,
      this.config.ollamaUrl
    );
    const assessmentResult = await assessmentAgent.run(context);

    if (!assessmentResult.success) {
      throw new Error(`Assessment failed: ${assessmentResult.error}`);
    }

    totalCost += assessmentResult.cost;
    context.previousResults!.assessment = assessmentResult.data;

    // Step 3: Run Threat Modeling Agent
    console.log('\n🎯 Phase 2: Threat Modeling');
    const threatAgent = new ThreatModelingAgent(
      this.config.model,
      this.config.provider,
      this.config.ollamaUrl
    );
    const threatResult = await threatAgent.run(context);

    if (!threatResult.success) {
      throw new Error(`Threat modeling failed: ${threatResult.error}`);
    }

    totalCost += threatResult.cost;
    context.previousResults!.threatModel = threatResult.data;

    // Step 4: Run Code Review Agent
    console.log('\n🔬 Phase 3: Code Review');
    const codeReviewAgent = new CodeReviewAgent(
      this.config.model,
      this.config.provider,
      this.config.ollamaUrl
    );
    const codeReviewResult = await codeReviewAgent.run(context);

    if (!codeReviewResult.success) {
      throw new Error(`Code review failed: ${codeReviewResult.error}`);
    }

    totalCost += codeReviewResult.cost;
    context.previousResults!.vulnerabilities = codeReviewResult.data;

    // Step 5: Run Report Generator
    console.log('\n📝 Phase 4: Report Generation');
    const reportAgent = new ReportGeneratorAgent(
      this.config.model,
      this.config.provider,
      this.config.ollamaUrl
    );
    const reportResult = await reportAgent.run(context);

    if (!reportResult.success) {
      throw new Error(`Report generation failed: ${reportResult.error}`);
    }

    totalCost += reportResult.cost;

    // Step 6: Run Smart Contract Scanners (if enabled and Solidity files exist)
    let smartContractVulns: ScanReport['smartContractVulnerabilities'] = [];
    let arcVulns: ScanReport['arcVulnerabilities'] = [];

    if (this.config.includeSmartContracts) {
      const hasSolidity = context.files.some(f => f.path.endsWith('.sol'));

      if (hasSolidity) {
        console.log('\n🔗 Phase 5: Smart Contract Analysis');

        // Run Slither (if installed)
        const slitherInstalled = await isSlitherInstalled();
        if (slitherInstalled) {
          console.log('[Slither] Running static analysis...');
          const slitherVulns = await runSlither(workDir);
          console.log(`[Slither] Found ${slitherVulns.length} issues`);
          smartContractVulns.push(...slitherVulns);
        } else {
          console.log('[Slither] Not installed - skipping');
          console.log('[Slither] Install with: pip install slither-analyzer');
        }

        // Run Mythril (if installed)
        const mythrilInstalled = await isMythrilInstalled();
        if (mythrilInstalled) {
          console.log('[Mythril] Running symbolic execution...');
          const mythrilVulns = await runMythril(workDir);
          console.log(`[Mythril] Found ${mythrilVulns.length} issues`);
          smartContractVulns.push(...mythrilVulns);
        } else {
          console.log('[Mythril] Not installed - skipping');
          console.log('[Mythril] Install with: pip install mythril');
        }

        // Run Arc-specific scanner
        console.log('[Arc Scanner] Checking for Arc-specific vulnerabilities...');
        arcVulns = await runArcScanner(context.files);
        console.log(`[Arc Scanner] Found ${arcVulns.length} issues`);
      }
    }

    // Step 7: Run GenLayer Scanner (if enabled and GenLayer contracts exist)
    let genLayerVulns: ScanReport['genLayerVulnerabilities'] = [];

    if (this.config.includeGenLayer) {
      const hasGenLayer = hasGenLayerContracts(context.files);

      if (hasGenLayer) {
        console.log('\n🧠 Phase 6: GenLayer Intelligent Contract Analysis');
        genLayerVulns = await runGenLayerScanner(context.files);
        console.log(`[GenLayer] Found ${genLayerVulns.length} issues`);
      } else {
        console.log('\n[GenLayer] No intelligent contracts found - skipping');
      }
    }

    const duration = Date.now() - startTime;

    // Merge code review vulnerabilities with rule-based vulnerabilities
    const codeReviewData = codeReviewResult.data as ScanReport['vulnerabilities'];
    const allCodeVulns = [...codeReviewData.vulnerabilities, ...ruleBasedVulns];

    // Deduplicate by file+line (prefer rule-based as they're more specific)
    const vulnMap = new Map<string, typeof allCodeVulns[0]>();
    for (const vuln of allCodeVulns) {
      const key = `${vuln.filePath}:${vuln.lineNumber}`;
      if (!vulnMap.has(key)) {
        vulnMap.set(key, vuln);
      }
    }

    // Tag vulnerabilities with third-party info and calculate priority scores
    // Per OWASP Vulnerable Dependency Management guidance
    const deduplicatedVulns = tagVulnerabilities(Array.from(vulnMap.values())).map(vuln => ({
      ...vuln,
      priorityScore: calculatePriorityScore(vuln),
    }));

    // Sort by priority score (highest first) for actionable triage
    deduplicatedVulns.sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0));

    // Split into first-party and third-party for separate reporting
    const { firstParty, thirdParty } = splitVulnerabilities(deduplicatedVulns);
    const firstPartySummary = calculateSummary(firstParty);
    const thirdPartySummary = calculateSummary(thirdParty);

    // Create placeholder report
    const report: ScanReport = {
      id: `scan_${Date.now()}`,
      timestamp: new Date().toISOString(),
      target: this.config.target,
      targetType: this.config.targetType,
      duration,
      cost: totalCost,
      score: 0, // Will be calculated after all agents run
      assessment: assessmentResult.data as ScanReport['assessment'],
      threatModel: threatResult.data as ScanReport['threatModel'],
      vulnerabilities: {
        ...codeReviewData,
        vulnerabilities: deduplicatedVulns,
        summary: {
          ...codeReviewData.summary,
          total: deduplicatedVulns.length,
          bySeverity: {
            critical: deduplicatedVulns.filter(v => v.severity === 'critical').length,
            high: deduplicatedVulns.filter(v => v.severity === 'high').length,
            medium: deduplicatedVulns.filter(v => v.severity === 'medium').length,
            low: deduplicatedVulns.filter(v => v.severity === 'low').length,
            info: deduplicatedVulns.filter(v => v.severity === 'info').length,
          },
        },
      },
      smartContractVulnerabilities: smartContractVulns,
      arcVulnerabilities: arcVulns,
      genLayerVulnerabilities: genLayerVulns,
      summary: {
        totalIssues: deduplicatedVulns.length +
                     smartContractVulns.length + arcVulns.length + genLayerVulns.length,
        critical: deduplicatedVulns.filter(v => v.severity === 'critical').length +
                  smartContractVulns.filter(v => v.severity === 'critical').length +
                  arcVulns.filter(v => v.severity === 'critical').length +
                  genLayerVulns.filter(v => v.severity === 'critical').length,
        high: deduplicatedVulns.filter(v => v.severity === 'high').length +
              smartContractVulns.filter(v => v.severity === 'high').length +
              arcVulns.filter(v => v.severity === 'high').length +
              genLayerVulns.filter(v => v.severity === 'high').length,
        medium: deduplicatedVulns.filter(v => v.severity === 'medium').length +
                smartContractVulns.filter(v => v.severity === 'medium').length +
                arcVulns.filter(v => v.severity === 'medium').length +
                genLayerVulns.filter(v => v.severity === 'medium').length,
        low: deduplicatedVulns.filter(v => v.severity === 'low').length +
             smartContractVulns.filter(v => v.severity === 'low').length +
             arcVulns.filter(v => v.severity === 'low').length +
             genLayerVulns.filter(v => v.severity === 'low').length,
        info: deduplicatedVulns.filter(v => v.severity === 'info').length +
              smartContractVulns.filter(v => v.severity === 'info').length +
              arcVulns.filter(v => v.severity === 'info').length +
              genLayerVulns.filter(v => v.severity === 'info').length,
      },
      // OWASP/NIST SBOM aligned: Separate first-party vs third-party summaries
      firstPartySummary,
      thirdPartySummary,
      badge: {
        eligible: false, // Will be calculated after summary is complete
        reason: '',
      },
    };

    // Calculate security score using combined summary
    report.score = this.calculateSecurityScore(report);

    // Calculate badge eligibility using combined summary
    report.badge.eligible = this.calculateBadgeEligibility(report.summary);
    report.badge.reason = this.getBadgeReason(report.summary);

    console.log('\n✅ Security scan complete!');
    console.log(`   Duration: ${(duration / 1000).toFixed(1)}s`);
    console.log(`   Cost: $${totalCost.toFixed(4)}`);
    console.log(`   Security Score: ${report.score}/100`);
    console.log('');
    console.log('📄 Generated Reports:');
    console.log(`   ${workDir}/SECURITY.md`);
    console.log(`   ${workDir}/THREATS.md`);
    console.log(`   ${workDir}/VULNERABILITIES.md`);
    console.log(`   ${workDir}/REPORT.md`);
    console.log(`   ${workDir}/arcshield-report.json`);
    console.log('');
    console.log(`   Total Issues: ${report.summary.totalIssues}`);
    console.log(`   🔴 Critical: ${report.summary.critical}`);
    console.log(`   🟠 High: ${report.summary.high}`);
    console.log(`   🟡 Medium: ${report.summary.medium}`);
    console.log(`   🟢 Low: ${report.summary.low}`);
    console.log('');
    // OWASP/NIST SBOM: Show first-party vs third-party breakdown
    console.log('📊 First-Party vs Third-Party Breakdown:');
    console.log(`   🏠 Your Code: ${firstPartySummary.totalIssues} issues (${firstPartySummary.critical} critical, ${firstPartySummary.high} high)`);
    console.log(`   📦 Dependencies: ${thirdPartySummary.totalIssues} issues (${thirdPartySummary.critical} critical, ${thirdPartySummary.high} high)`);

    // Write final JSON report with all results (including smart contract findings)
    const jsonPath = path.join(workDir, 'arcshield-report.json');
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf-8');

    return report;
  }

  /**
   * Run a FREE rule-only scan (no AI, just pattern matching)
   * Uses 75+ built-in security rules - completely free
   */
  async scanRulesOnly(): Promise<ScanReport> {
    const startTime = Date.now();

    console.log('\n🛡️  ArcShield Quick Scan (Rules Only)');
    console.log('━'.repeat(50));

    // Step 1: Discover files
    console.log('\n📂 Discovering files...');
    const workDir = path.resolve(this.config.target);
    const files = await walkFiles({ rootDir: workDir });
    console.log(`   Found ${files.length} files to analyze`);

    // Step 2: Run Rule Engine (pattern-based scanning)
    console.log('\n📋 Running Rule-Based Scanner...');
    const engine = await this.getRuleEngine();
    const stats = engine.getStats();
    console.log(`   Loaded ${stats.total} rules across ${Object.keys(stats.byCategory).length} categories`);

    const matches = engine.scan(files);
    const rawVulns = engine.toVulnerabilities(matches);
    console.log(`   Found ${rawVulns.length} issues via pattern matching`);

    // Step 3: Run Arc Scanner (also pattern-based, free)
    let arcVulns: ScanReport['arcVulnerabilities'] = [];
    const hasSolidity = files.some(f => f.path.endsWith('.sol'));
    if (hasSolidity) {
      console.log('\n🔗 Running Arc-Specific Scanner...');
      arcVulns = await runArcScanner(files);
      console.log(`   Found ${arcVulns.length} Arc-specific issues`);
    }

    const duration = Date.now() - startTime;

    // Tag vulnerabilities with third-party info and priority scores (OWASP/NIST aligned)
    const ruleBasedVulns = tagVulnerabilities(rawVulns).map(vuln => ({
      ...vuln,
      priorityScore: calculatePriorityScore(vuln),
    }));

    // Sort by priority score (highest first)
    ruleBasedVulns.sort((a, b) => (b.priorityScore || 0) - (a.priorityScore || 0));

    // Split into first-party and third-party
    const { firstParty, thirdParty } = splitVulnerabilities(ruleBasedVulns);
    const firstPartySummary = calculateSummary(firstParty);
    const thirdPartySummary = calculateSummary(thirdParty);

    // Build summary
    const summary = {
      totalIssues: ruleBasedVulns.length + arcVulns.length,
      critical: ruleBasedVulns.filter(v => v.severity === 'critical').length +
                arcVulns.filter(v => v.severity === 'critical').length,
      high: ruleBasedVulns.filter(v => v.severity === 'high').length +
            arcVulns.filter(v => v.severity === 'high').length,
      medium: ruleBasedVulns.filter(v => v.severity === 'medium').length +
              arcVulns.filter(v => v.severity === 'medium').length,
      low: ruleBasedVulns.filter(v => v.severity === 'low').length +
           arcVulns.filter(v => v.severity === 'low').length,
      info: ruleBasedVulns.filter(v => v.severity === 'info').length +
            arcVulns.filter(v => v.severity === 'info').length,
    };

    // Create report (minimal - no AI analysis)
    const report: ScanReport = {
      id: `scan_${Date.now()}`,
      timestamp: new Date().toISOString(),
      target: this.config.target,
      targetType: this.config.targetType,
      duration,
      cost: 0, // FREE - no AI cost
      score: 0,
      scanType: 'rules-only', // Mark as rules-only scan
      assessment: {
        applicationType: 'Unknown (Quick Scan)',
        frameworks: [],
        entryPoints: [],
        dataFlows: [],
        securityFeatures: [],
        filesAnalyzed: files.length,
        linesOfCode: files.reduce((acc, f) => acc + (f.content?.split('\n').length || 0), 0),
      },
      threatModel: {
        threats: [],
        summary: {
          total: 0,
          byCategory: {
            spoofing: 0,
            tampering: 0,
            repudiation: 0,
            information_disclosure: 0,
            denial_of_service: 0,
            elevation_of_privilege: 0,
          },
          bySeverity: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
          },
        },
      },
      vulnerabilities: {
        vulnerabilities: ruleBasedVulns,
        summary: {
          total: ruleBasedVulns.length,
          bySeverity: {
            critical: ruleBasedVulns.filter(v => v.severity === 'critical').length,
            high: ruleBasedVulns.filter(v => v.severity === 'high').length,
            medium: ruleBasedVulns.filter(v => v.severity === 'medium').length,
            low: ruleBasedVulns.filter(v => v.severity === 'low').length,
            info: ruleBasedVulns.filter(v => v.severity === 'info').length,
          },
        },
      },
      smartContractVulnerabilities: [],
      arcVulnerabilities: arcVulns,
      genLayerVulnerabilities: [],
      summary,
      // OWASP/NIST SBOM aligned: Separate first-party vs third-party summaries
      firstPartySummary,
      thirdPartySummary,
      badge: {
        eligible: summary.critical === 0 && summary.high === 0,
        reason: summary.critical > 0 ? `${summary.critical} critical vulnerabilities` :
                summary.high > 0 ? `${summary.high} high severity vulnerabilities` :
                'Meets basic security requirements (Full AI Scan recommended)',
      },
    };

    // Calculate score
    report.score = this.calculateSecurityScore(report);

    console.log('\n✅ Quick scan complete!');
    console.log(`   Duration: ${(duration / 1000).toFixed(1)}s`);
    console.log(`   Cost: FREE`);
    console.log(`   Security Score: ${report.score}/100`);
    console.log(`   Total Issues: ${summary.totalIssues}`);
    console.log('');
    // OWASP/NIST SBOM: Show first-party vs third-party breakdown
    console.log('📊 First-Party vs Third-Party Breakdown:');
    console.log(`   🏠 Your Code: ${firstPartySummary.totalIssues} issues (${firstPartySummary.critical} critical, ${firstPartySummary.high} high)`);
    console.log(`   📦 Dependencies: ${thirdPartySummary.totalIssues} issues (${thirdPartySummary.critical} critical, ${thirdPartySummary.high} high)`);
    console.log('');
    console.log('💡 For deeper analysis (STRIDE threats, AI code review),');
    console.log('   run a Full AI Scan.');

    return report;
  }

  /**
   * Run only the assessment phase
   */
  async assess(): Promise<ScanReport['assessment']> {
    const workDir = path.resolve(this.config.target);
    const files = await walkFiles({ rootDir: workDir });

    const context: AgentContext = {
      workDir,
      files,
      config: this.config,
    };

    const agent = new AssessmentAgent(
      this.config.model,
      this.config.provider,
      this.config.ollamaUrl
    );
    const result = await agent.run(context);

    if (!result.success) {
      throw new Error(`Assessment failed: ${result.error}`);
    }

    return result.data as ScanReport['assessment'];
  }

  /**
   * Get current configuration
   */
  getConfig(): ScanConfig {
    return { ...this.config };
  }

  /**
   * Calculate security score (0-100)
   * Includes ALL vulnerabilities: code review + arc scanner + smart contracts
   */
  private calculateSecurityScore(report: ScanReport): number {
    // Start with perfect score
    let score = 100;

    // Use the combined summary which includes all vulnerability sources
    score -= report.summary.critical * 25; // Critical = -25 each
    score -= report.summary.high * 15;     // High = -15 each
    score -= report.summary.medium * 8;    // Medium = -8 each
    score -= report.summary.low * 3;       // Low = -3 each
    // Info doesn't affect score

    // Ensure score is between 0 and 100
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Check if eligible for ArcShield Verified badge
   * Uses combined summary which includes all vulnerability sources
   */
  private calculateBadgeEligibility(summary: ScanReport['summary']): boolean {
    // No critical or high vulnerabilities allowed from ANY source
    return summary.critical === 0 && summary.high === 0;
  }

  /**
   * Get reason for badge status
   * Uses combined summary which includes all vulnerability sources
   */
  private getBadgeReason(summary: ScanReport['summary']): string {
    if (summary.critical > 0) {
      return `${summary.critical} critical vulnerabilities must be fixed`;
    }
    if (summary.high > 0) {
      return `${summary.high} high severity vulnerabilities must be fixed`;
    }
    return 'Meets security requirements';
  }
}
