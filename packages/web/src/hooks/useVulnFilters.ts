import { useState, useMemo, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import type { Vulnerability, ArcVulnerability, Severity } from '../types';
import type { VulnFilters, SortConfig } from '../types';
import { filterVulnerabilities, sortVulnerabilities, createDefaultFilters, createDefaultSort, countBySeverity } from '../utils/filters';

type VulnItem = Vulnerability | ArcVulnerability;

interface UseVulnFiltersReturn {
  // Filter state
  filters: VulnFilters;
  sortConfig: SortConfig;

  // Filtered/sorted results
  filteredVulns: VulnItem[];

  // Counts
  totalCount: number;
  filteredCount: number;
  severityCounts: Record<Severity, number>;

  // Actions
  setSearch: (search: string) => void;
  toggleSeverity: (severity: Severity) => void;
  setSeverities: (severities: Severity[]) => void;
  setIsThirdParty: (value: boolean | null) => void;
  setFilePath: (path: string | null) => void;
  setSort: (config: SortConfig) => void;
  resetFilters: () => void;

  // Quick preset actions
  applyPreset: (preset: FilterPreset) => void;

  // Check if any filters active
  hasActiveFilters: boolean;
}

export interface FilterPreset {
  id: string;
  name: string;
  icon?: string;
  filters: Partial<VulnFilters>;
}

// Built-in presets
export const DEFAULT_PRESETS: FilterPreset[] = [
  {
    id: 'critical',
    name: 'Critical',
    icon: '🔥',
    filters: { severities: ['critical'] },
  },
  {
    id: 'high',
    name: 'High',
    icon: '⚠️',
    filters: { severities: ['high'] },
  },
  {
    id: 'critical-high',
    name: 'Critical & High',
    icon: '🚨',
    filters: { severities: ['critical', 'high'] },
  },
  {
    id: 'my-code',
    name: 'My Code',
    icon: '🏠',
    filters: { isThirdParty: false },
  },
  {
    id: 'dependencies',
    name: 'Dependencies',
    icon: '📦',
    filters: { isThirdParty: true },
  },
];

export function useVulnFilters(vulnerabilities: VulnItem[]): UseVulnFiltersReturn {
  const [searchParams, setSearchParams] = useSearchParams();

  // Initialize filters from URL or defaults
  const getInitialFilters = useCallback((): VulnFilters => {
    const search = searchParams.get('search') || '';
    const severitiesParam = searchParams.get('severities');
    const severities = severitiesParam ? severitiesParam.split(',') as Severity[] : [];
    const thirdPartyParam = searchParams.get('thirdParty');
    const isThirdParty = thirdPartyParam === null ? null : thirdPartyParam === 'true';
    const filePath = searchParams.get('file') || null;

    return { search, severities, isThirdParty, filePath };
  }, [searchParams]);

  const getInitialSort = useCallback((): SortConfig => {
    const field = searchParams.get('sortBy') as SortConfig['field'] || 'severity';
    const order = searchParams.get('sortOrder') as SortConfig['order'] || 'desc';
    return { field, order };
  }, [searchParams]);

  const [filters, setFilters] = useState<VulnFilters>(getInitialFilters);
  const [sortConfig, setSortConfig] = useState<SortConfig>(getInitialSort);

  // Sync filters to URL
  const updateUrlParams = useCallback((newFilters: VulnFilters, newSort: SortConfig) => {
    const params = new URLSearchParams();

    if (newFilters.search) params.set('search', newFilters.search);
    if (newFilters.severities.length > 0) params.set('severities', newFilters.severities.join(','));
    if (newFilters.isThirdParty !== null) params.set('thirdParty', String(newFilters.isThirdParty));
    if (newFilters.filePath) params.set('file', newFilters.filePath);
    if (newSort.field !== 'severity') params.set('sortBy', newSort.field);
    if (newSort.order !== 'desc') params.set('sortOrder', newSort.order);

    setSearchParams(params, { replace: true });
  }, [setSearchParams]);

  // Filter and sort the vulnerabilities
  const filteredVulns = useMemo(() => {
    const filtered = filterVulnerabilities(vulnerabilities, filters);
    return sortVulnerabilities(filtered, sortConfig);
  }, [vulnerabilities, filters, sortConfig]);

  // Counts
  const totalCount = vulnerabilities.length;
  const filteredCount = filteredVulns.length;
  const severityCounts = useMemo(() => countBySeverity(vulnerabilities), [vulnerabilities]);

  // Check if any filters are active
  const hasActiveFilters = useMemo(() => {
    return (
      filters.search !== '' ||
      filters.severities.length > 0 ||
      filters.isThirdParty !== null ||
      filters.filePath !== null
    );
  }, [filters]);

  // Actions
  const setSearch = useCallback((search: string) => {
    const newFilters = { ...filters, search };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [filters, sortConfig, updateUrlParams]);

  const toggleSeverity = useCallback((severity: Severity) => {
    const newSeverities = filters.severities.includes(severity)
      ? filters.severities.filter(s => s !== severity)
      : [...filters.severities, severity];
    const newFilters = { ...filters, severities: newSeverities };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [filters, sortConfig, updateUrlParams]);

  const setSeverities = useCallback((severities: Severity[]) => {
    const newFilters = { ...filters, severities };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [filters, sortConfig, updateUrlParams]);

  const setIsThirdParty = useCallback((value: boolean | null) => {
    const newFilters = { ...filters, isThirdParty: value };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [filters, sortConfig, updateUrlParams]);

  const setFilePath = useCallback((path: string | null) => {
    const newFilters = { ...filters, filePath: path };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [filters, sortConfig, updateUrlParams]);

  const setSort = useCallback((config: SortConfig) => {
    setSortConfig(config);
    updateUrlParams(filters, config);
  }, [filters, updateUrlParams]);

  const resetFilters = useCallback(() => {
    const defaultFilters = createDefaultFilters();
    const defaultSort = createDefaultSort();
    setFilters(defaultFilters);
    setSortConfig(defaultSort);
    setSearchParams({}, { replace: true });
  }, [setSearchParams]);

  const applyPreset = useCallback((preset: FilterPreset) => {
    const newFilters = {
      ...createDefaultFilters(),
      ...preset.filters,
    };
    setFilters(newFilters);
    updateUrlParams(newFilters, sortConfig);
  }, [sortConfig, updateUrlParams]);

  return {
    filters,
    sortConfig,
    filteredVulns,
    totalCount,
    filteredCount,
    severityCounts,
    setSearch,
    toggleSeverity,
    setSeverities,
    setIsThirdParty,
    setFilePath,
    setSort,
    resetFilters,
    applyPreset,
    hasActiveFilters,
  };
}
