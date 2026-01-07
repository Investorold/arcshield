/**
 * ArcShield Agents
 *
 * Multi-agent pipeline for security analysis:
 * 1. Assessment Agent - Maps codebase architecture
 * 2. Threat Modeling Agent - Applies STRIDE framework
 * 3. Code Review Agent - Validates vulnerabilities
 * 4. Report Generator - Compiles findings
 * 5. DAST Agent - Dynamic testing (optional)
 * 6. Smart Contract Threat Agent - Contract-specific analysis
 */

export { BaseAgent, type ModelType, type AgentMessage } from './base-agent.js';
export { AssessmentAgent } from './assessment.js';
export { ThreatModelingAgent } from './threat-modeling.js';
export { CodeReviewAgent } from './code-review.js';
export { ReportGeneratorAgent } from './report-generator.js';

// Agent names for reference
export const AGENTS = {
  assessment: 'assessment',
  threatModeling: 'threat-modeling',
  codeReview: 'code-review',
  reportGenerator: 'report-generator',
  dast: 'dast',
  smartContractThreat: 'smart-contract-threat',
} as const;

export type AgentName = (typeof AGENTS)[keyof typeof AGENTS];
