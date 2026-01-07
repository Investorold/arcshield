/**
 * Code Review Agent (Agent 3)
 *
 * Analyzes code for security vulnerabilities
 *
 * Responsibilities:
 * - Validate threats from Agent 2 against actual code
 * - Find specific vulnerable code locations
 * - Apply security rules (Arc, GenLayer, web)
 * - Provide code-level remediation guidance
 *
 * Input: Threat model from Agent 2, Assessment from Agent 1
 * Output: VULNERABILITIES.md with specific code issues
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
  Vulnerability,
  Severity,
  FileContext,
  AIProvider,
} from '../types/index.js';

// Load security rules
const loadRules = (rulesDir: string): SecurityRule[] => {
  const rules: SecurityRule[] = [];
  const ruleFiles = ['arc-rules.json', 'genlayer-rules.json', 'web-rules.json'];

  for (const file of ruleFiles) {
    try {
      const filePath = path.join(rulesDir, file);
      if (fs.existsSync(filePath)) {
        const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
        if (content.rules) {
          rules.push(...content.rules);
        }
      }
    } catch {
      // Ignore missing rule files
    }
  }

  return rules;
};

interface SecurityRule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  pattern?: string;
  detection: string;
  recommendation: string;
  cweId?: string;
}

const SYSTEM_PROMPT = `You are an expert security code reviewer specializing in finding vulnerabilities in web applications, APIs, and smart contracts.

Your task is to analyze code files and identify specific security vulnerabilities.

## Analysis Approach

1. **Review each threat** from the threat model
2. **Search the code** for patterns that could enable that threat
3. **Identify specific vulnerabilities** with exact file locations and line numbers
4. **Provide actionable remediation** for each finding

## Common Vulnerability Patterns

### Authentication & Authorization
- Hardcoded credentials or API keys
- Missing authentication checks
- Broken access control
- Session management issues

### Injection Flaws
- SQL injection
- Command injection
- XSS (Cross-Site Scripting)
- Path traversal

### Data Exposure
- Sensitive data in logs
- Unencrypted storage
- Exposed error messages
- Information leakage

### Smart Contract Issues
- Reentrancy vulnerabilities
- Integer overflow/underflow
- Unchecked external calls
- Access control issues

### Arc-Specific Issues
- Incorrect decimal handling (18 vs 6)
- Reliance on block.prevrandao
- Timestamp dependencies

Be precise with line numbers and provide specific code fixes.`;

const ANALYSIS_PROMPT = `Review the following code files for security vulnerabilities based on the identified threats.

## Identified Threats

{threats}

## Security Rules to Apply

{rules}

## Code Files to Review

{files}

---

For each vulnerability found, provide:
1. A unique ID (VULN-001, VULN-002, etc.)
2. Link to the related threat ID
3. The exact file path and line number
4. A code snippet showing the vulnerable code
5. Severity assessment
6. Clear explanation of the issue
7. How an attacker could exploit it
8. Specific code fix or remediation

Respond in the following JSON format:

\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "Brief vulnerability title",
      "severity": "critical|high|medium|low|info",
      "threatId": "THREAT-XXX (the related threat)",
      "description": "Detailed description of the vulnerability",
      "filePath": "exact/path/to/file.ts",
      "lineNumber": 42,
      "codeSnippet": "The vulnerable code snippet",
      "cweId": "CWE-XXX (if applicable)",
      "exploitability": "How an attacker could exploit this",
      "remediation": "Specific steps to fix this vulnerability",
      "aiFixPrompt": "A prompt that could be used to ask an AI to fix this code"
    }
  ]
}
\`\`\`

Focus on real, exploitable vulnerabilities. Avoid false positives.`;

export class CodeReviewAgent extends BaseAgent {
  name = 'Code Review Agent';
  description = 'Analyzes code for security vulnerabilities';

  private rules: SecurityRule[] = [];

  constructor(model: ModelType = 'sonnet', provider: AIProvider = 'anthropic', ollamaUrl?: string) {
    super(model, 16384, provider, ollamaUrl); // Larger context for code analysis

    // Load security rules
    const rulesDir = path.join(__dirname, '..', 'rules');
    this.rules = loadRules(rulesDir);
  }

  async run(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.resetTokens();
    this.log('Starting code review...');

    try {
      // Get previous results
      const assessment = context.previousResults?.assessment as AssessmentResult;
      const threatModel = context.previousResults?.threatModel as ThreatModelResult;

      if (!assessment) {
        throw new Error('Assessment results not found. Run Assessment Agent first.');
      }

      if (!threatModel) {
        throw new Error('Threat model not found. Run Threat Modeling Agent first.');
      }

      this.log(`Reviewing code against ${threatModel.threats.length} threats...`);
      this.log(`Applying ${this.rules.length} security rules...`);

      // Prioritize files for security review
      const prioritizedFiles = this.prioritizeFilesForReview(context.files);
      this.log(`Analyzing ${prioritizedFiles.length} priority files...`);

      // Build the analysis prompt
      const prompt = this.buildPrompt(threatModel, prioritizedFiles);

      // Get vulnerability analysis from Claude
      this.log('Sending to AI for code analysis...');
      const response = await this.chat(SYSTEM_PROMPT, [
        { role: 'user', content: prompt },
      ]);

      // Parse the response
      const parsed = this.parseJSON<{ vulnerabilities: Vulnerability[] }>(response);

      if (!parsed || !parsed.vulnerabilities) {
        throw new Error('Failed to parse code review response');
      }

      // Build the result with summary
      const result: VulnerabilityResult = {
        vulnerabilities: parsed.vulnerabilities,
        summary: this.buildSummary(parsed.vulnerabilities),
      };

      // Generate VULNERABILITIES.md
      const vulnMd = this.generateVulnerabilitiesMd(result, context);
      const outputPath = path.join(context.workDir, 'VULNERABILITIES.md');
      fs.writeFileSync(outputPath, vulnMd, 'utf-8');
      this.log(`Generated ${outputPath}`);

      const duration = Date.now() - startTime;
      const cost = this.calculateCost();

      this.log(`Code review complete: ${result.vulnerabilities.length} vulnerabilities found`);
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
   * Prioritize files that are more likely to have security issues
   */
  private prioritizeFilesForReview(files: FileContext[]): FileContext[] {
    const highPriorityPatterns = [
      // Authentication & Authorization
      /auth/i,
      /login/i,
      /session/i,
      /password/i,
      /token/i,
      /jwt/i,
      /oauth/i,

      // API & Routes
      /api\//,
      /routes?\//,
      /controllers?\//,
      /handlers?\//,
      /middleware/i,

      // Data handling
      /database/i,
      /db\./,
      /query/i,
      /sql/i,

      // Smart contracts
      /\.sol$/,
      /contracts?\//,

      // Configuration
      /config/i,
      /\.env/,

      // Security-related
      /security/i,
      /crypto/i,
      /encrypt/i,
      /validation/i,
      /sanitize/i,
    ];

    const scoredFiles = files.map(file => {
      let score = 0;
      for (let i = 0; i < highPriorityPatterns.length; i++) {
        if (highPriorityPatterns[i].test(file.path)) {
          score += 10;
        }
      }

      // Also consider file size (larger files might have more issues)
      if (file.lines > 100) score += 2;
      if (file.lines > 300) score += 3;

      return { file, score };
    });

    // Sort by score and return top files
    return scoredFiles
      .sort((a, b) => b.score - a.score)
      .map(sf => sf.file);
  }

  /**
   * Build the analysis prompt
   */
  private buildPrompt(threatModel: ThreatModelResult, files: FileContext[]): string {
    // Format threats
    const threatsList = threatModel.threats
      .map(t => `- ${t.id}: ${t.title} (${t.category}, ${t.severity})`)
      .join('\n');

    // Format rules
    const rulesList = this.rules
      .slice(0, 20) // Limit to avoid token overflow
      .map(r => `- ${r.id}: ${r.name} (${r.severity}) - ${r.description}`)
      .join('\n');

    // Format files with code
    const filesContext = this.formatFilesForContext(files);

    return ANALYSIS_PROMPT
      .replace('{threats}', threatsList || 'No specific threats identified')
      .replace('{rules}', rulesList || 'No custom rules loaded')
      .replace('{files}', filesContext);
  }

  /**
   * Build summary statistics
   */
  private buildSummary(vulnerabilities: Vulnerability[]): VulnerabilityResult['summary'] {
    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const vuln of vulnerabilities) {
      if (bySeverity[vuln.severity] !== undefined) {
        bySeverity[vuln.severity]++;
      }
    }

    return {
      total: vulnerabilities.length,
      bySeverity,
    };
  }

  /**
   * Generate VULNERABILITIES.md
   */
  private generateVulnerabilitiesMd(result: VulnerabilityResult, context: AgentContext): string {
    const timestamp = new Date().toISOString();

    const severityEmoji: Record<Severity, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: 'ℹ️',
    };

    let md = `# Vulnerability Report

> Generated by ArcShield Code Review Agent
> Date: ${timestamp}
> Target: ${context.config.target}

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${result.summary.bySeverity.critical} |
| 🟠 High | ${result.summary.bySeverity.high} |
| 🟡 Medium | ${result.summary.bySeverity.medium} |
| 🟢 Low | ${result.summary.bySeverity.low} |
| ℹ️ Info | ${result.summary.bySeverity.info} |
| **Total** | **${result.summary.total}** |

---

`;

    if (result.vulnerabilities.length === 0) {
      md += `## No Vulnerabilities Found

Great news! No vulnerabilities were identified in the code review.

However, this does not guarantee the absence of security issues. Consider:
- Manual penetration testing
- Dynamic application security testing (DAST)
- Regular security audits

---
`;
    } else {
      // Group vulnerabilities by severity
      const criticalVulns = result.vulnerabilities.filter(v => v.severity === 'critical');
      const highVulns = result.vulnerabilities.filter(v => v.severity === 'high');
      const mediumVulns = result.vulnerabilities.filter(v => v.severity === 'medium');
      const lowVulns = result.vulnerabilities.filter(v => v.severity === 'low');
      const infoVulns = result.vulnerabilities.filter(v => v.severity === 'info');

      const addVulnSection = (vulns: Vulnerability[], title: string) => {
        if (vulns.length === 0) return;

        md += `## ${title}\n\n`;

        for (const vuln of vulns) {
          md += `### ${severityEmoji[vuln.severity]} ${vuln.id}: ${vuln.title}

**Severity:** ${vuln.severity.toUpperCase()}
**File:** \`${vuln.filePath}:${vuln.lineNumber}\`
**Related Threat:** ${vuln.threatId}
${vuln.cweId ? `**CWE:** ${vuln.cweId}` : ''}

#### Description

${vuln.description}

#### Vulnerable Code

\`\`\`
${vuln.codeSnippet}
\`\`\`

#### Exploitability

${vuln.exploitability}

#### Remediation

${vuln.remediation}

<details>
<summary>AI Fix Prompt</summary>

\`\`\`
${vuln.aiFixPrompt}
\`\`\`

</details>

---

`;
        }
      };

      addVulnSection(criticalVulns, '🔴 Critical Vulnerabilities');
      addVulnSection(highVulns, '🟠 High Vulnerabilities');
      addVulnSection(mediumVulns, '🟡 Medium Vulnerabilities');
      addVulnSection(lowVulns, '🟢 Low Vulnerabilities');
      addVulnSection(infoVulns, 'ℹ️ Informational');
    }

    md += `
---

*This report is generated automatically and should be reviewed by a security professional.*
`;

    return md;
  }
}
