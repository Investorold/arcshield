/**
 * Threat Modeling Agent (Agent 2)
 *
 * Applies STRIDE framework to identify security threats
 *
 * STRIDE Categories:
 * - Spoofing: Pretending to be someone/something else
 * - Tampering: Modifying data or code maliciously
 * - Repudiation: Denying actions without proof
 * - Information Disclosure: Exposing data to unauthorized parties
 * - Denial of Service: Making system unavailable
 * - Elevation of Privilege: Gaining unauthorized access
 *
 * Input: Assessment results from Agent 1
 * Output: THREATS.md file with prioritized threat list
 */

import * as fs from 'fs';
import * as path from 'path';
import { BaseAgent, type ModelType } from './base-agent.js';
import type {
  AgentContext,
  AgentResult,
  AssessmentResult,
  ThreatModelResult,
  Threat,
  StrideCategory,
  Severity,
  AIProvider,
} from '../types/index.js';

const SYSTEM_PROMPT = `You are an expert security threat modeler with deep knowledge of the STRIDE framework.

Your task is to analyze an application's architecture and identify potential security threats.

## STRIDE Framework

For each component and data flow, consider:

1. **Spoofing** (Authentication)
   - Can an attacker pretend to be another user or system?
   - Are there weak authentication mechanisms?
   - Can tokens/sessions be stolen or forged?

2. **Tampering** (Integrity)
   - Can data be modified in transit or at rest?
   - Are there unsigned transactions or messages?
   - Can code or configuration be altered?

3. **Repudiation** (Non-repudiation)
   - Can users deny performing actions?
   - Is there adequate logging and audit trails?
   - Are transactions properly signed?

4. **Information Disclosure** (Confidentiality)
   - Can sensitive data be exposed?
   - Are there data leaks through logs, errors, or APIs?
   - Is encryption properly implemented?

5. **Denial of Service** (Availability)
   - Can the system be overwhelmed?
   - Are there resource exhaustion vectors?
   - Can attackers block legitimate users?

6. **Elevation of Privilege** (Authorization)
   - Can users access unauthorized functions?
   - Are there privilege escalation paths?
   - Is access control properly enforced?

Be thorough and specific. Each threat should be actionable.`;

const ANALYSIS_PROMPT = `Based on the following security assessment, identify potential security threats using the STRIDE framework.

## Assessment Results

**Application Type:** {applicationType}

**Frameworks:** {frameworks}

**Entry Points:**
{entryPoints}

**Data Flows:**
{dataFlows}

**Authentication Mechanisms:**
{authMechanisms}

**External Dependencies:**
{externalDependencies}

**Sensitive Data Paths:**
{sensitiveDataPaths}

**Existing Security Controls:**
{securityControls}

---

Analyze each component and data flow for potential threats. For each threat identified, provide:

1. A unique ID (THREAT-001, THREAT-002, etc.)
2. A clear title
3. The STRIDE category
4. Severity (critical, high, medium, low, info)
5. Detailed description
6. Affected components
7. A realistic attack scenario
8. Recommended mitigation
9. CWE ID if applicable

Respond in the following JSON format:

\`\`\`json
{
  "threats": [
    {
      "id": "THREAT-001",
      "title": "Brief threat title",
      "category": "spoofing|tampering|repudiation|information_disclosure|denial_of_service|elevation_of_privilege",
      "severity": "critical|high|medium|low|info",
      "description": "Detailed description of the threat",
      "affectedComponents": ["list of affected components/files"],
      "attackScenario": "Step-by-step description of how an attacker could exploit this",
      "cweId": "CWE-XXX (if applicable)",
      "mitigation": "Specific steps to mitigate this threat"
    }
  ]
}
\`\`\`

Prioritize threats by severity. Be specific and actionable.`;

export class ThreatModelingAgent extends BaseAgent {
  name = 'Threat Modeling Agent';
  description = 'Applies STRIDE framework to identify security threats';

  constructor(model: ModelType = 'sonnet', provider: AIProvider = 'anthropic', ollamaUrl?: string) {
    super(model, 8192, provider, ollamaUrl);
  }

  async run(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.resetTokens();
    this.log('Starting threat modeling...');

    try {
      // Get assessment results from previous agent
      const assessment = context.previousResults?.assessment as AssessmentResult;

      if (!assessment) {
        throw new Error('Assessment results not found. Run Assessment Agent first.');
      }

      this.log('Analyzing assessment for potential threats...');

      // Build the analysis prompt with assessment data
      const prompt = this.buildPrompt(assessment);

      // Get threat analysis from Claude
      this.log('Sending to AI for threat analysis...');
      const response = await this.chat(SYSTEM_PROMPT, [
        { role: 'user', content: prompt },
      ]);

      // Parse the response
      const parsed = this.parseJSON<{ threats: Threat[] }>(response);

      if (!parsed || !parsed.threats) {
        // Log the response for debugging
        this.log(`Raw response (first 500 chars): ${response.substring(0, 500)}`);

        // Try to provide an empty result instead of failing
        this.log('Warning: Could not parse AI response, returning empty threat list');
        const emptyResult: ThreatModelResult = {
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
        };

        const duration = Date.now() - startTime;
        return {
          success: true,
          data: emptyResult,
          duration,
          cost: this.calculateCost(),
        };
      }

      // Build the result with summary
      const result: ThreatModelResult = {
        threats: parsed.threats,
        summary: this.buildSummary(parsed.threats),
      };

      // Generate THREATS.md
      const threatsMd = this.generateThreatsMd(result, context);
      const outputPath = path.join(context.workDir, 'THREATS.md');
      fs.writeFileSync(outputPath, threatsMd, 'utf-8');
      this.log(`Generated ${outputPath}`);

      const duration = Date.now() - startTime;
      const cost = this.calculateCost();

      this.log(`Threat modeling complete: ${result.threats.length} threats identified`);
      this.log(`  Critical: ${result.summary.bySeverity.critical}`);
      this.log(`  High: ${result.summary.bySeverity.high}`);
      this.log(`  Medium: ${result.summary.bySeverity.medium}`);
      this.log(`  Low: ${result.summary.bySeverity.low}`);
      this.log(`Cost: $${cost.toFixed(4)}`);

      return {
        success: true,
        data: result,
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
   * Build the prompt from assessment data
   */
  private buildPrompt(assessment: AssessmentResult): string {
    const entryPoints = assessment.architecture.entryPoints
      .map(e => `- ${e}`)
      .join('\n') || '- None identified';

    const dataFlows = assessment.dataFlows
      .map(df => `- ${df.source} → ${df.destination} (${df.dataType}): ${df.description}`)
      .join('\n') || '- None identified';

    const authMechanisms = assessment.authMechanisms
      .map(a => `- ${a}`)
      .join('\n') || '- None identified';

    const externalDeps = assessment.externalDependencies
      .map(d => `- ${d}`)
      .join('\n') || '- None identified';

    const sensitivePaths = assessment.sensitiveDataPaths
      .map(p => `- ${p}`)
      .join('\n') || '- None identified';

    const securityControls = assessment.securityControls
      .map(c => `- ${c}`)
      .join('\n') || '- None identified';

    return ANALYSIS_PROMPT
      .replace('{applicationType}', assessment.architecture.type)
      .replace('{frameworks}', assessment.architecture.frameworks.join(', '))
      .replace('{entryPoints}', entryPoints)
      .replace('{dataFlows}', dataFlows)
      .replace('{authMechanisms}', authMechanisms)
      .replace('{externalDependencies}', externalDeps)
      .replace('{sensitiveDataPaths}', sensitivePaths)
      .replace('{securityControls}', securityControls);
  }

  /**
   * Build summary statistics from threats
   */
  private buildSummary(threats: Threat[]): ThreatModelResult['summary'] {
    const byCategory: Record<StrideCategory, number> = {
      spoofing: 0,
      tampering: 0,
      repudiation: 0,
      information_disclosure: 0,
      denial_of_service: 0,
      elevation_of_privilege: 0,
    };

    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const threat of threats) {
      if (byCategory[threat.category] !== undefined) {
        byCategory[threat.category]++;
      }
      if (bySeverity[threat.severity] !== undefined) {
        bySeverity[threat.severity]++;
      }
    }

    return {
      total: threats.length,
      byCategory,
      bySeverity,
    };
  }

  /**
   * Generate THREATS.md from analysis
   */
  private generateThreatsMd(result: ThreatModelResult, context: AgentContext): string {
    const timestamp = new Date().toISOString();

    const severityEmoji: Record<Severity, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: 'ℹ️',
    };

    const categoryDescriptions: Record<StrideCategory, string> = {
      spoofing: 'Identity/Authentication attacks',
      tampering: 'Data/Code integrity attacks',
      repudiation: 'Non-repudiation failures',
      information_disclosure: 'Data exposure risks',
      denial_of_service: 'Availability attacks',
      elevation_of_privilege: 'Authorization bypass',
    };

    // Group threats by severity
    const criticalThreats = result.threats.filter(t => t.severity === 'critical');
    const highThreats = result.threats.filter(t => t.severity === 'high');
    const mediumThreats = result.threats.filter(t => t.severity === 'medium');
    const lowThreats = result.threats.filter(t => t.severity === 'low');
    const infoThreats = result.threats.filter(t => t.severity === 'info');

    let md = `# Threat Model

> Generated by ArcShield Threat Modeling Agent
> Date: ${timestamp}
> Target: ${context.config.target}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Threats | ${result.summary.total} |
| 🔴 Critical | ${result.summary.bySeverity.critical} |
| 🟠 High | ${result.summary.bySeverity.high} |
| 🟡 Medium | ${result.summary.bySeverity.medium} |
| 🟢 Low | ${result.summary.bySeverity.low} |
| ℹ️ Info | ${result.summary.bySeverity.info} |

### By STRIDE Category

| Category | Description | Count |
|----------|-------------|-------|
| Spoofing | ${categoryDescriptions.spoofing} | ${result.summary.byCategory.spoofing} |
| Tampering | ${categoryDescriptions.tampering} | ${result.summary.byCategory.tampering} |
| Repudiation | ${categoryDescriptions.repudiation} | ${result.summary.byCategory.repudiation} |
| Information Disclosure | ${categoryDescriptions.information_disclosure} | ${result.summary.byCategory.information_disclosure} |
| Denial of Service | ${categoryDescriptions.denial_of_service} | ${result.summary.byCategory.denial_of_service} |
| Elevation of Privilege | ${categoryDescriptions.elevation_of_privilege} | ${result.summary.byCategory.elevation_of_privilege} |

---

`;

    // Add threats by severity
    const addThreatSection = (threats: Threat[], title: string) => {
      if (threats.length === 0) return;

      md += `## ${title}\n\n`;

      for (const threat of threats) {
        md += `### ${severityEmoji[threat.severity]} ${threat.id}: ${threat.title}

**Category:** ${threat.category.replace('_', ' ').toUpperCase()}
**Severity:** ${threat.severity.toUpperCase()}
${threat.cweId ? `**CWE:** ${threat.cweId}` : ''}

#### Description

${threat.description}

#### Affected Components

${threat.affectedComponents.map(c => `- \`${c}\``).join('\n')}

#### Attack Scenario

${threat.attackScenario}

#### Mitigation

${threat.mitigation}

---

`;
      }
    };

    addThreatSection(criticalThreats, '🔴 Critical Threats');
    addThreatSection(highThreats, '🟠 High Threats');
    addThreatSection(mediumThreats, '🟡 Medium Threats');
    addThreatSection(lowThreats, '🟢 Low Threats');
    addThreatSection(infoThreats, 'ℹ️ Informational');

    md += `
---

*This threat model is generated automatically using the STRIDE framework and should be reviewed by a security professional.*
`;

    return md;
  }
}
