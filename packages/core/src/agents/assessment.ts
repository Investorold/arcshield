/**
 * Assessment Agent (Agent 1)
 *
 * Maps codebase architecture and generates SECURITY.md
 *
 * Responsibilities:
 * - Analyze application architecture and component structure
 * - Document data flow patterns between components
 * - Identify authentication/authorization mechanisms
 * - Catalog external dependencies and API integrations
 * - Map sensitive data handling paths
 * - List entry points (APIs, forms, CLI commands)
 * - Document existing security controls
 *
 * Output: SECURITY.md file
 */

import * as fs from 'fs';
import * as path from 'path';
import { BaseAgent, type ModelType } from './base-agent.js';
import type { AgentContext, AgentResult, AssessmentResult, DataFlow, FileContext, AIProvider } from '../types/index.js';
import { getFileSummary, getTotalLines } from '../utils/file-walker.js';

const SYSTEM_PROMPT = `You are a senior security architect performing a comprehensive security assessment of a codebase.

Your task is to analyze the provided code and generate a detailed security assessment document.

Focus on:
1. **Architecture**: What type of application is this? (web app, API, smart contract, CLI tool, etc.)
2. **Frameworks & Technologies**: What frameworks, libraries, and technologies are used?
3. **Entry Points**: Where does user input enter the system? (API endpoints, forms, CLI args, etc.)
4. **Data Flows**: How does data move through the system? What sensitive data exists?
5. **Authentication**: How is authentication handled? What mechanisms are used?
6. **External Dependencies**: What external services, APIs, or databases are used?
7. **Security Controls**: What existing security measures are in place?

Be thorough but concise. Focus on security-relevant architectural aspects.`;

const ANALYSIS_PROMPT = `Analyze this codebase and provide a security assessment.

## Codebase Statistics
- Total Files: {fileCount}
- Total Lines: {totalLines}
- Languages: {languages}

## Files to Analyze
{files}

---

Provide your analysis in the following JSON format:

\`\`\`json
{
  "architecture": {
    "type": "string - e.g., 'Web Application', 'REST API', 'Smart Contract', 'Full-Stack dApp'",
    "frameworks": ["list of frameworks detected"],
    "entryPoints": ["list of entry points - APIs, forms, CLI commands, etc."]
  },
  "dataFlows": [
    {
      "source": "where data originates",
      "destination": "where data goes",
      "dataType": "type of data (user input, credentials, PII, etc.)",
      "description": "brief description of this flow"
    }
  ],
  "authMechanisms": ["list of authentication mechanisms found"],
  "externalDependencies": ["list of external services, APIs, databases"],
  "sensitiveDataPaths": ["paths where sensitive data is handled"],
  "securityControls": ["existing security measures found"],
  "technologies": ["all technologies/libraries detected"]
}
\`\`\`

Be specific and cite file paths where relevant.`;

export class AssessmentAgent extends BaseAgent {
  name = 'Assessment Agent';
  description = 'Analyzes codebase architecture and generates SECURITY.md';

  constructor(model: ModelType = 'sonnet', provider: AIProvider = 'anthropic', ollamaUrl?: string) {
    super(model, 8192, provider, ollamaUrl);
  }

  async run(context: AgentContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.resetTokens();
    this.log('Starting codebase assessment...');

    try {
      // Get file statistics
      const fileSummary = getFileSummary(context.files);
      const totalLines = getTotalLines(context.files);
      const languages = Object.entries(fileSummary)
        .map(([lang, count]) => `${lang}: ${count}`)
        .join(', ');

      this.log(`Analyzing ${context.files.length} files (${totalLines} lines)`);

      // Prioritize important files for analysis
      const prioritizedFiles = this.prioritizeFiles(context.files);

      // Format files for context
      const filesContext = this.formatFilesForContext(prioritizedFiles);

      // Build the analysis prompt
      const prompt = ANALYSIS_PROMPT
        .replace('{fileCount}', context.files.length.toString())
        .replace('{totalLines}', totalLines.toString())
        .replace('{languages}', languages)
        .replace('{files}', filesContext);

      // Get analysis from Claude
      this.log('Sending to AI for analysis...');
      const response = await this.chat(SYSTEM_PROMPT, [
        { role: 'user', content: prompt },
      ]);

      // Parse the response
      const analysis = this.parseJSON<AssessmentResult>(response);

      if (!analysis) {
        throw new Error('Failed to parse assessment response');
      }

      // Add file statistics
      analysis.fileCount = context.files.length;
      analysis.totalLines = totalLines;

      // Generate SECURITY.md
      const securityMd = this.generateSecurityMd(analysis, context);

      // Write SECURITY.md to output
      const outputPath = path.join(context.workDir, 'SECURITY.md');
      fs.writeFileSync(outputPath, securityMd, 'utf-8');
      this.log(`Generated ${outputPath}`);

      const duration = Date.now() - startTime;
      const cost = this.calculateCost();

      this.log(`Assessment complete (${(duration / 1000).toFixed(1)}s, $${cost.toFixed(4)})`);

      return {
        success: true,
        data: analysis,
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
   * Prioritize important files for analysis
   */
  private prioritizeFiles(files: FileContext[]): FileContext[] {
    const priorityPatterns = [
      // Config files (highest priority)
      /package\.json$/,
      /tsconfig\.json$/,
      /hardhat\.config/,
      /foundry\.toml$/,
      /\.env\.example$/,

      // Entry points
      /index\.(ts|js|tsx|jsx)$/,
      /main\.(ts|js)$/,
      /app\.(ts|js|tsx|jsx)$/,
      /server\.(ts|js)$/,

      // Routes and API
      /routes?\//,
      /api\//,
      /controllers?\//,
      /handlers?\//,

      // Auth
      /auth/i,
      /login/i,
      /session/i,

      // Smart contracts
      /\.sol$/,
      /contracts?\//,

      // Security-related
      /security/i,
      /middleware/i,
      /validation/i,
    ];

    // Score each file based on priority patterns
    const scoredFiles = files.map(file => {
      let score = 0;
      for (let i = 0; i < priorityPatterns.length; i++) {
        if (priorityPatterns[i].test(file.path)) {
          score += priorityPatterns.length - i; // Higher priority = higher score
        }
      }
      return { file, score };
    });

    // Sort by score (descending) and return files
    return scoredFiles
      .sort((a, b) => b.score - a.score)
      .map(sf => sf.file);
  }

  /**
   * Generate SECURITY.md from analysis
   */
  private generateSecurityMd(analysis: AssessmentResult, context: AgentContext): string {
    const timestamp = new Date().toISOString();

    let md = `# Security Assessment

> Generated by ArcShield Assessment Agent
> Date: ${timestamp}
> Target: ${context.config.target}

---

## Overview

| Metric | Value |
|--------|-------|
| Total Files | ${analysis.fileCount} |
| Total Lines | ${analysis.totalLines} |
| Application Type | ${analysis.architecture.type} |

---

## Architecture

**Type:** ${analysis.architecture.type}

### Frameworks & Technologies

${analysis.architecture.frameworks.map(f => `- ${f}`).join('\n')}

### Entry Points

${analysis.architecture.entryPoints.map(e => `- ${e}`).join('\n')}

---

## Data Flows

| Source | Destination | Data Type | Description |
|--------|-------------|-----------|-------------|
${analysis.dataFlows.map((df: DataFlow) => `| ${df.source} | ${df.destination} | ${df.dataType} | ${df.description} |`).join('\n')}

---

## Authentication Mechanisms

${analysis.authMechanisms.length > 0
  ? analysis.authMechanisms.map(a => `- ${a}`).join('\n')
  : '- No authentication mechanisms detected'}

---

## External Dependencies

${analysis.externalDependencies.length > 0
  ? analysis.externalDependencies.map(d => `- ${d}`).join('\n')
  : '- No external dependencies detected'}

---

## Sensitive Data Paths

${analysis.sensitiveDataPaths.length > 0
  ? analysis.sensitiveDataPaths.map(p => `- \`${p}\``).join('\n')
  : '- No sensitive data paths identified'}

---

## Existing Security Controls

${analysis.securityControls.length > 0
  ? analysis.securityControls.map(c => `- ${c}`).join('\n')
  : '- No security controls detected'}

---

## Technologies Detected

${analysis.technologies.map(t => `- ${t}`).join('\n')}

---

*This document is generated automatically and should be reviewed by a security professional.*
`;

    return md;
  }
}
