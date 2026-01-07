/**
 * ArcShield Core
 * Multi-Agent AI Security Scanner for Arc Ecosystem
 */

import * as path from 'path';
import type { ScanConfig, ScanReport, AgentContext } from './types/index.js';
import { walkFiles } from './utils/file-walker.js';
import { AssessmentAgent } from './agents/assessment.js';
import { BADGE_THRESHOLD } from './constants.js';

// Export types
export * from './types/index.js';

// Export constants
export * from './constants.js';

// Export utilities
export * from './utils/index.js';

// Export agents
export * from './agents/index.js';

// Version
export const VERSION = '0.1.0';

// Main Scanner class
export class Scanner {
  private config: ScanConfig;

  constructor(config: Partial<ScanConfig> = {}) {
    this.config = {
      target: config.target || '.',
      targetType: config.targetType || 'local',
      includeSmartContracts: config.includeSmartContracts ?? true,
      includeWebApp: config.includeWebApp ?? true,
      includeGenLayer: config.includeGenLayer ?? false,
      model: config.model || 'sonnet',
      outputFormat: config.outputFormat || 'json',
      outputPath: config.outputPath,
    };
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

    // Step 2: Run Assessment Agent
    console.log('\n🔍 Phase 1: Assessment');
    const assessmentAgent = new AssessmentAgent(this.config.model);
    const assessmentResult = await assessmentAgent.run(context);

    if (!assessmentResult.success) {
      throw new Error(`Assessment failed: ${assessmentResult.error}`);
    }

    totalCost += assessmentResult.cost;
    context.previousResults!.assessment = assessmentResult.data;

    // TODO: Step 3: Run Threat Modeling Agent (Phase 1 continued)
    // TODO: Step 4: Run Code Review Agent (Phase 1 continued)
    // TODO: Step 5: Run Smart Contract Scanner (Phase 2)
    // TODO: Step 6: Generate Final Report (Phase 1 continued)

    const duration = Date.now() - startTime;

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
        vulnerabilities: [],
        summary: {
          total: 0,
          bySeverity: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
          },
        },
      },
      summary: {
        totalIssues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      badge: {
        eligible: false,
        reason: 'Scan incomplete - additional agents not yet implemented',
      },
    };

    console.log('\n✅ Assessment phase complete!');
    console.log(`   Duration: ${(duration / 1000).toFixed(1)}s`);
    console.log(`   Cost: $${totalCost.toFixed(4)}`);
    console.log(`   Output: ${workDir}/SECURITY.md`);
    console.log('\n⚠️  Note: Threat Modeling and Code Review agents coming next!');

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

    const agent = new AssessmentAgent(this.config.model);
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
}
