/**
 * ArcShield Core Types
 */

// Severity levels for vulnerabilities
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// STRIDE threat categories
export type StrideCategory =
  | 'spoofing'
  | 'tampering'
  | 'repudiation'
  | 'information_disclosure'
  | 'denial_of_service'
  | 'elevation_of_privilege';

// Scan target types
export type ScanTargetType = 'github' | 'local' | 'contract_address' | 'url';

// AI Provider types
export type AIProvider = 'anthropic' | 'ollama';

// Model types per provider
export type AnthropicModel = 'haiku' | 'sonnet' | 'opus';
export type OllamaModel = 'llama3' | 'llama3.1' | 'mistral' | 'codellama' | 'mixtral' | 'deepseek-coder';

// Scan configuration
export interface ScanConfig {
  target: string;
  targetType: ScanTargetType;
  includeSmartContracts: boolean;
  includeWebApp: boolean;
  includeGenLayer: boolean;
  provider: AIProvider;
  model: string; // AnthropicModel or OllamaModel
  ollamaUrl?: string; // Default: http://localhost:11434
  outputFormat: 'json' | 'markdown' | 'html';
  outputPath?: string;
}

// File context for scanning
export interface FileContext {
  path: string;
  content: string;
  language: string;
  lines: number;
}

// Codebase assessment result (Agent 1 output)
export interface AssessmentResult {
  architecture: {
    type: string;
    frameworks: string[];
    entryPoints: string[];
  };
  dataFlows: DataFlow[];
  authMechanisms: string[];
  externalDependencies: string[];
  sensitiveDataPaths: string[];
  securityControls: string[];
  technologies: string[];
  fileCount: number;
  totalLines: number;
}

// Quick assessment for rules-only scans (no AI)
export interface QuickAssessment {
  applicationType: string;
  frameworks: string[];
  entryPoints: string[];
  dataFlows: string[];
  securityFeatures: string[];
  filesAnalyzed: number;
  linesOfCode: number;
}

export interface DataFlow {
  source: string;
  destination: string;
  dataType: string;
  description: string;
}

// Threat model result (Agent 2 output)
export interface ThreatModelResult {
  threats: Threat[];
  summary: {
    total: number;
    byCategory: Record<StrideCategory, number>;
    bySeverity: Record<Severity, number>;
  };
}

export interface Threat {
  id: string;
  title: string;
  category: StrideCategory;
  severity: Severity;
  description: string;
  affectedComponents: string[];
  attackScenario: string;
  cweId?: string;
  mitigation: string;
}

// Vulnerability result (Agent 3 output)
export interface VulnerabilityResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    bySeverity: Record<Severity, number>;
  };
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  threatId: string;
  description: string;
  filePath: string;
  lineNumber: number;
  codeSnippet: string;
  cweId?: string;
  exploitability: string;
  remediation: string;
  aiFixPrompt: string;
}

// Smart contract specific vulnerability
export interface SmartContractVulnerability extends Vulnerability {
  contractName: string;
  functionName?: string;
  detector: string;
  tool: 'slither' | 'mythril' | 'arcshield';
}

// Arc-specific vulnerability
export interface ArcVulnerability extends SmartContractVulnerability {
  arcSpecific: true;
  arcRule: string;
}

// GenLayer-specific vulnerability
export interface GenLayerVulnerability extends Vulnerability {
  genLayerSpecific: true;
  genLayerRule: string;
  promptRelated: boolean;
}

// Scan type - rules-only (free) or full AI scan
export type ScanType = 'rules-only' | 'ai-full';

// Final scan report
export interface ScanReport {
  id: string;
  timestamp: string;
  target: string;
  targetType: ScanTargetType;
  duration: number;
  cost: number;
  score: number;
  scanType?: ScanType; // 'rules-only' for free scans, 'ai-full' for paid AI scans
  assessment: AssessmentResult | QuickAssessment;
  threatModel: ThreatModelResult;
  vulnerabilities: VulnerabilityResult;
  smartContractVulnerabilities?: SmartContractVulnerability[];
  arcVulnerabilities?: ArcVulnerability[];
  genLayerVulnerabilities?: GenLayerVulnerability[];
  summary: {
    totalIssues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  badge: {
    eligible: boolean;
    reason?: string;
  };
}

// Agent interface
export interface Agent {
  name: string;
  description: string;
  run(context: AgentContext): Promise<AgentResult>;
}

export interface AgentContext {
  workDir: string;
  files: FileContext[];
  previousResults?: Record<string, unknown>;
  config: ScanConfig;
}

export interface AgentResult {
  success: boolean;
  data: unknown;
  error?: string;
  duration: number;
  cost: number;
}
