/**
 * Report Generator Agent (Agent 4)
 *
 * Compiles findings from all agents into a comprehensive security report
 *
 * Responsibilities:
 * - Aggregate all scan results
 * - Generate executive summary
 * - Provide prioritized recommendations
 * - Create final REPORT.md
 * - Support multiple output formats
 *
 * Input: All previous agent results
 * Output: REPORT.md (or JSON/HTML based on config)
 */

import * as fs from 'fs';
import * as path from 'path';
import { BaseAgent, type ModelType } from './base-agent.js';
import type {
  AgentContext,
  AgentResult,
  AssessmentResult,
  ThreatModelResult,
  VulnerabilityResult,
  ScanReport,
  Severity,
} from '../types/index.js';

const SYSTEM_PROMPT = `You are a senior security consultant preparing an executive security report.

Your task is to analyze security findings and provide:
1. A clear executive summary suitable for non-technical stakeholders
2. Prioritized recommendations for remediation
3. Risk assessment based on the findings

Be concise but thorough. Focus on business impact and actionable recommendations.`;

const SUMMARY_PROMPT = `Based on the following security scan results, provide an executive summary and recommendations.

## Scan Overview

**Target:** {target}
**Scan Duration:** {duration}
**Security Score:** {score}/100

## Findings Summary

**Threats Identified:** {threatCount}
- Spoofing: {spoofing}
- Tampering: {tampering}
- Repudiation: {repudiation}
- Information Disclosure: {infoDisclosure}
- Denial of Service: {dos}
- Elevation of Privilege: {eop}

**Vulnerabilities Found:** {vulnCount}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Informational: {info}

## Top Vulnerabilities

{topVulnerabilities}

---

Provide your analysis in the following JSON format:

\`\`\`json
{
  "executiveSummary": "2-3 paragraph summary suitable for executives and non-technical stakeholders",
  "riskLevel": "critical|high|medium|low",
  "recommendations": [
    {
      "priority": 1,
      "title": "Brief recommendation title",
      "description": "Detailed description of what to do",
      "effort": "low|medium|high",
      "impact": "Description of security impact if implemented"
    }
  ],
  "complianceNotes": "Any compliance-related observations (OWASP, CWE, etc.)"
}
\`\`\``;

interface ReportData {
  executiveSummary: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  recommendations: Array<{
    priority: number;
    title: string;
    description: string;
    effort: 'low' | 'medium' | 'high';
    impact: string;
  }>;
  complianceNotes: string;
}

export class ReportGeneratorAgent extends BaseAgent {
  name = 'Report Generator Agent';
  description = 'Generates comprehensive security report';

  constructor(model: ModelType = 'sonnet') {
    super(model, 4096);
  }

  async run(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.resetTokens();
    this.log('Generating security report...');

    try {
      // Get all previous results
      const assessment = context.previousResults?.assessment as AssessmentResult;
      const threatModel = context.previousResults?.threatModel as ThreatModelResult;
      const vulnerabilities = context.previousResults?.vulnerabilities as VulnerabilityResult;

      if (!assessment || !threatModel || !vulnerabilities) {
        throw new Error('Missing required scan results. Run all previous agents first.');
      }

      // Calculate score
      const score = this.calculateScore(vulnerabilities);

      // Build the prompt
      const prompt = this.buildPrompt(context, assessment, threatModel, vulnerabilities, score);

      // Get AI analysis
      this.log('Analyzing findings for executive summary...');
      const response = await this.chat(SYSTEM_PROMPT, [
        { role: 'user', content: prompt },
      ]);

      // Parse the response
      const reportData = this.parseJSON<ReportData>(response);

      if (!reportData) {
        throw new Error('Failed to parse report generator response');
      }

      // Generate the final report
      const report = this.generateReport(
        context,
        assessment,
        threatModel,
        vulnerabilities,
        reportData,
        score
      );

      // Write report based on output format
      const outputPath = this.writeReport(context, report);
      this.log(`Generated ${outputPath}`);

      const duration = Date.now() - startTime;
      const cost = this.calculateCost();

      this.log(`Report generation complete (${(duration / 1000).toFixed(1)}s, $${cost.toFixed(4)})`);

      return {
        success: true,
        data: {
          ...reportData,
          score,
          outputPath,
        },
        duration,
        cost,
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      this.log(`Error: ${errorMessage}`);

      return {
        success: false,
        data: null,
        error: errorMessage,
        duration,
        cost: this.calculateCost(),
      };
    }
  }

  /**
   * Calculate security score
   */
  private calculateScore(vulnerabilities: VulnerabilityResult): number {
    let score = 100;
    const bySeverity = vulnerabilities.summary.bySeverity;

    score -= bySeverity.critical * 25;
    score -= bySeverity.high * 15;
    score -= bySeverity.medium * 8;
    score -= bySeverity.low * 3;

    return Math.max(0, Math.min(100, score));
  }

  /**
   * Build the analysis prompt
   */
  private buildPrompt(
    context: AgentContext,
    assessment: AssessmentResult,
    threatModel: ThreatModelResult,
    vulnerabilities: VulnerabilityResult,
    score: number
  ): string {
    // Get top vulnerabilities for context
    const topVulns = vulnerabilities.vulnerabilities
      .sort((a, b) => {
        const severityOrder: Record<Severity, number> = {
          critical: 0,
          high: 1,
          medium: 2,
          low: 3,
          info: 4,
        };
        return severityOrder[a.severity] - severityOrder[b.severity];
      })
      .slice(0, 5)
      .map(v => `- [${v.severity.toUpperCase()}] ${v.title}: ${v.description.slice(0, 100)}...`)
      .join('\n');

    return SUMMARY_PROMPT
      .replace('{target}', context.config.target)
      .replace('{duration}', 'N/A')
      .replace('{score}', score.toString())
      .replace('{threatCount}', threatModel.summary.total.toString())
      .replace('{spoofing}', threatModel.summary.byCategory.spoofing.toString())
      .replace('{tampering}', threatModel.summary.byCategory.tampering.toString())
      .replace('{repudiation}', threatModel.summary.byCategory.repudiation.toString())
      .replace('{infoDisclosure}', threatModel.summary.byCategory.information_disclosure.toString())
      .replace('{dos}', threatModel.summary.byCategory.denial_of_service.toString())
      .replace('{eop}', threatModel.summary.byCategory.elevation_of_privilege.toString())
      .replace('{vulnCount}', vulnerabilities.summary.total.toString())
      .replace('{critical}', vulnerabilities.summary.bySeverity.critical.toString())
      .replace('{high}', vulnerabilities.summary.bySeverity.high.toString())
      .replace('{medium}', vulnerabilities.summary.bySeverity.medium.toString())
      .replace('{low}', vulnerabilities.summary.bySeverity.low.toString())
      .replace('{info}', vulnerabilities.summary.bySeverity.info.toString())
      .replace('{topVulnerabilities}', topVulns || 'No vulnerabilities found');
  }

  /**
   * Generate the complete report
   */
  private generateReport(
    context: AgentContext,
    assessment: AssessmentResult,
    threatModel: ThreatModelResult,
    vulnerabilities: VulnerabilityResult,
    reportData: ReportData,
    score: number
  ): string {
    const timestamp = new Date().toISOString();
    const badgeEligible = vulnerabilities.summary.bySeverity.critical === 0 &&
                          vulnerabilities.summary.bySeverity.high === 0;

    const riskEmoji: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
    };

    let md = `# ArcShield Security Report

> Generated by ArcShield Security Scanner
> Date: ${timestamp}
> Target: ${context.config.target}

---

## Security Score

# ${score}/100 ${score >= 80 ? '✅' : score >= 50 ? '⚠️' : '❌'}

${badgeEligible
  ? '### 🏆 Eligible for ArcShield Verified Badge\n\nThis project meets the security requirements for the ArcShield Verified badge.'
  : '### ⚠️ Not Eligible for ArcShield Verified Badge\n\nCritical or high severity vulnerabilities must be resolved.'}

---

## Risk Assessment

**Overall Risk Level:** ${riskEmoji[reportData.riskLevel]} ${reportData.riskLevel.toUpperCase()}

---

## Executive Summary

${reportData.executiveSummary}

---

## Findings Overview

### Architecture

| Property | Value |
|----------|-------|
| Application Type | ${assessment.architecture.type} |
| Frameworks | ${assessment.architecture.frameworks.join(', ')} |
| Files Analyzed | ${assessment.fileCount} |
| Lines of Code | ${assessment.totalLines} |

### Threats (STRIDE Analysis)

| Category | Count |
|----------|-------|
| Spoofing | ${threatModel.summary.byCategory.spoofing} |
| Tampering | ${threatModel.summary.byCategory.tampering} |
| Repudiation | ${threatModel.summary.byCategory.repudiation} |
| Information Disclosure | ${threatModel.summary.byCategory.information_disclosure} |
| Denial of Service | ${threatModel.summary.byCategory.denial_of_service} |
| Elevation of Privilege | ${threatModel.summary.byCategory.elevation_of_privilege} |
| **Total** | **${threatModel.summary.total}** |

### Vulnerabilities

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${vulnerabilities.summary.bySeverity.critical} |
| 🟠 High | ${vulnerabilities.summary.bySeverity.high} |
| 🟡 Medium | ${vulnerabilities.summary.bySeverity.medium} |
| 🟢 Low | ${vulnerabilities.summary.bySeverity.low} |
| ℹ️ Info | ${vulnerabilities.summary.bySeverity.info} |
| **Total** | **${vulnerabilities.summary.total}** |

---

## Prioritized Recommendations

${reportData.recommendations.map((rec, i) => `
### ${i + 1}. ${rec.title}

**Priority:** ${rec.priority} | **Effort:** ${rec.effort.toUpperCase()} | **Impact:** ${rec.impact}

${rec.description}
`).join('\n')}

---

## Compliance Notes

${reportData.complianceNotes}

---

## Detailed Reports

For detailed findings, see:
- [SECURITY.md](./SECURITY.md) - Architecture assessment
- [THREATS.md](./THREATS.md) - Threat model
- [VULNERABILITIES.md](./VULNERABILITIES.md) - Vulnerability details

---

## About ArcShield

ArcShield is a multi-agent AI security scanner designed for the Arc ecosystem.

**Agents Used:**
1. Assessment Agent - Codebase architecture analysis
2. Threat Modeling Agent - STRIDE framework analysis
3. Code Review Agent - Vulnerability detection
4. Report Generator - Comprehensive reporting

---

*This report is generated automatically and should be reviewed by a security professional.*
`;

    return md;
  }

  /**
   * Write report to file(s)
   */
  private writeReport(context: AgentContext, report: string): string {
    const format = context.config.outputFormat;
    const workDir = context.workDir;

    // Always write markdown report
    const mdPath = path.join(workDir, 'REPORT.md');
    fs.writeFileSync(mdPath, report, 'utf-8');

    // If JSON format requested, also output JSON
    if (format === 'json') {
      const jsonPath = context.config.outputPath || path.join(workDir, 'arcshield-report.json');
      const jsonReport: ScanReport = {
        id: `scan_${Date.now()}`,
        timestamp: new Date().toISOString(),
        target: context.config.target,
        targetType: context.config.targetType,
        duration: 0, // Will be set by scanner
        cost: 0, // Will be set by scanner
        score: this.calculateScore(context.previousResults?.vulnerabilities as VulnerabilityResult),
        assessment: context.previousResults?.assessment as ScanReport['assessment'],
        threatModel: context.previousResults?.threatModel as ScanReport['threatModel'],
        vulnerabilities: context.previousResults?.vulnerabilities as ScanReport['vulnerabilities'],
        summary: {
          totalIssues: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.total,
          critical: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.critical,
          high: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.high,
          medium: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.medium,
          low: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.low,
          info: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.info,
        },
        badge: {
          eligible: (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.critical === 0 &&
                   (context.previousResults?.vulnerabilities as VulnerabilityResult).summary.bySeverity.high === 0,
        },
      };
      fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2), 'utf-8');
      return jsonPath;
    }

    return mdPath;
  }
}
