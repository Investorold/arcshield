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

// Agents will be implemented in Phase 1
export const AGENTS = {
  assessment: 'assessment',
  threatModeling: 'threat-modeling',
  codeReview: 'code-review',
  reportGenerator: 'report-generator',
  dast: 'dast',
  smartContractThreat: 'smart-contract-threat',
} as const;

export type AgentName = (typeof AGENTS)[keyof typeof AGENTS];
