// Re-export types from core
export type {
  ScanReport,
  Severity,
  StrideCategory,
  AssessmentResult,
  ThreatModelResult,
  VulnerabilityResult,
  Vulnerability,
  Threat,
  SmartContractVulnerability,
  ArcVulnerability,
} from '@arcshield/core';

// Web-specific types
export interface ScanListItem {
  id: string;
  timestamp: string;
  target: string;
  score: number;
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanRequest {
  target: string;
  model?: string;
  provider?: string;
}

export interface ScanStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress?: number;
  message?: string;
}
