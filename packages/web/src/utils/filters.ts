import type { Vulnerability, ArcVulnerability, Severity } from '../types';
import { SEVERITY_ORDER } from '../types';
import type { VulnFilters, SortConfig } from '../types';

type VulnItem = Vulnerability | ArcVulnerability;

/**
 * Filter vulnerabilities based on filter criteria
 */
export function filterVulnerabilities(
  vulnerabilities: VulnItem[],
  filters: VulnFilters
): VulnItem[] {
  return vulnerabilities.filter((vuln) => {
    // Search filter (title, file path, CWE, description)
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      const matchesSearch =
        vuln.title.toLowerCase().includes(searchLower) ||
        vuln.filePath.toLowerCase().includes(searchLower) ||
        vuln.description.toLowerCase().includes(searchLower) ||
        (vuln.cweId && vuln.cweId.toLowerCase().includes(searchLower));
      if (!matchesSearch) return false;
    }

    // Severity filter
    if (filters.severities.length > 0) {
      if (!filters.severities.includes(vuln.severity)) return false;
    }

    // Third-party filter
    if (filters.isThirdParty !== null) {
      const isThirdParty = vuln.isThirdParty ?? false;
      if (filters.isThirdParty !== isThirdParty) return false;
    }

    // File path filter
    if (filters.filePath) {
      if (!vuln.filePath.toLowerCase().includes(filters.filePath.toLowerCase())) {
        return false;
      }
    }

    return true;
  });
}

/**
 * Sort vulnerabilities based on sort configuration
 */
export function sortVulnerabilities(
  vulnerabilities: VulnItem[],
  sortConfig: SortConfig
): VulnItem[] {
  const sorted = [...vulnerabilities].sort((a, b) => {
    let comparison = 0;

    switch (sortConfig.field) {
      case 'severity':
        comparison = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
        break;
      case 'file':
        comparison = a.filePath.localeCompare(b.filePath);
        break;
      case 'priority':
        const aPriority = a.priorityScore ?? 0;
        const bPriority = b.priorityScore ?? 0;
        comparison = bPriority - aPriority;
        break;
      case 'lineNumber':
        comparison = a.lineNumber - b.lineNumber;
        break;
    }

    return sortConfig.order === 'asc' ? comparison : -comparison;
  });

  return sorted;
}

/**
 * Count vulnerabilities by severity
 */
export function countBySeverity(
  vulnerabilities: VulnItem[]
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  vulnerabilities.forEach((vuln) => {
    counts[vuln.severity]++;
  });

  return counts;
}

/**
 * Create default filter state
 */
export function createDefaultFilters(): VulnFilters {
  return {
    search: '',
    severities: [],
    isThirdParty: null,
    filePath: null,
  };
}

/**
 * Create default sort configuration
 */
export function createDefaultSort(): SortConfig {
  return {
    field: 'severity',
    order: 'desc',
  };
}
