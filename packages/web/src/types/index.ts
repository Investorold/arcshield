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
  DependencyType,
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

// Vulnerability Filtering Types
export interface VulnFilters {
  search: string;
  severities: Severity[];
  isThirdParty: boolean | null; // null = show all, true = third-party only, false = first-party only
  filePath: string | null;
}

export interface SortConfig {
  field: 'severity' | 'file' | 'priority' | 'lineNumber';
  order: 'asc' | 'desc';
}

// Severity sort order (higher = more severe)
// Using explicit type since Severity is a type-only export
export const SEVERITY_ORDER: Record<'critical' | 'high' | 'medium' | 'low' | 'info', number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
