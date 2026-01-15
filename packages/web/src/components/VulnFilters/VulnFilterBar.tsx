import { useState, useEffect } from 'react';
import { X, Command } from 'lucide-react';
import SearchInput from '../common/SearchInput';
import QuickPresets from './QuickPresets';
import AdvancedFilters from './AdvancedFilters';
import SortDropdown from './SortDropdown';
import { DEFAULT_PRESETS, type FilterPreset } from '../../hooks/useVulnFilters';
import { useFilterPresets } from '../../hooks/useFilterPresets';
import type { Severity, VulnFilters, SortConfig } from '../../types';

interface VulnFilterBarProps {
  filters: VulnFilters;
  sortConfig: SortConfig;
  severityCounts: Record<Severity, number>;
  totalCount: number;
  filteredCount: number;
  hasActiveFilters: boolean;
  onSearchChange: (search: string) => void;
  onToggleSeverity: (severity: Severity) => void;
  onSetThirdParty: (value: boolean | null) => void;
  onSetFilePath: (path: string | null) => void;
  onSortChange: (config: SortConfig) => void;
  onApplyPreset: (preset: FilterPreset) => void;
  onResetFilters: () => void;
  onOpenCommandPalette?: () => void;
}

export default function VulnFilterBar({
  filters,
  sortConfig,
  severityCounts,
  totalCount,
  filteredCount,
  hasActiveFilters,
  onSearchChange,
  onToggleSeverity,
  onSetThirdParty,
  onSetFilePath,
  onSortChange,
  onApplyPreset,
  onResetFilters,
  onOpenCommandPalette,
}: VulnFilterBarProps) {
  const { presets: savedPresets, savePreset, deletePreset } = useFilterPresets();
  const [activePresetId, setActivePresetId] = useState<string | null>(null);

  // Detect which preset is active based on current filters
  useEffect(() => {
    const allPresets = [...DEFAULT_PRESETS, ...savedPresets];
    const activePreset = allPresets.find((preset) => {
      const presetFilters = preset.filters;

      // Check severities match
      if (presetFilters.severities) {
        if (
          presetFilters.severities.length !== filters.severities.length ||
          !presetFilters.severities.every((s) => filters.severities.includes(s))
        ) {
          return false;
        }
      } else if (filters.severities.length > 0) {
        return false;
      }

      // Check isThirdParty matches
      if (presetFilters.isThirdParty !== undefined) {
        if (presetFilters.isThirdParty !== filters.isThirdParty) {
          return false;
        }
      } else if (filters.isThirdParty !== null) {
        return false;
      }

      // If preset has filters and they all match
      return true;
    });

    setActivePresetId(activePreset?.id || null);
  }, [filters, savedPresets]);

  const handlePresetSelect = (preset: FilterPreset | { id: string; filters: Partial<VulnFilters> }) => {
    onApplyPreset(preset as FilterPreset);
  };

  return (
    <div className="space-y-3">
      {/* Row 1: Quick Presets + Cmd+K shortcut */}
      <div className="flex items-center justify-between">
        <QuickPresets
          defaultPresets={DEFAULT_PRESETS}
          savedPresets={savedPresets}
          activePresetId={activePresetId}
          onSelectPreset={handlePresetSelect}
          onSavePreset={savePreset}
          onDeletePreset={deletePreset}
          currentFilters={filters}
          hasActiveFilters={hasActiveFilters}
        />

        {onOpenCommandPalette && (
          <button
            onClick={onOpenCommandPalette}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-700/50 hover:bg-gray-700 rounded text-sm text-gray-400 hover:text-white transition-colors"
            title="Open command palette (Cmd+K)"
          >
            <Command className="w-3.5 h-3.5" />
            <span>K</span>
          </button>
        )}
      </div>

      {/* Row 2: Search + Advanced + Sort + Clear */}
      <div className="flex items-center gap-3">
        <SearchInput
          value={filters.search}
          onChange={onSearchChange}
          placeholder="Search by title, file path, CWE, description..."
          className="flex-1"
        />

        <SortDropdown sortConfig={sortConfig} onSortChange={onSortChange} />

        {hasActiveFilters && (
          <button
            onClick={onResetFilters}
            className="flex items-center gap-1.5 px-3 py-2 bg-gray-700 hover:bg-red-500/20 hover:text-red-400 rounded text-sm text-gray-400 transition-colors"
            title="Clear all filters"
          >
            <X className="w-4 h-4" />
            Clear
          </button>
        )}
      </div>

      {/* Row 3: Advanced Filters (collapsible) */}
      <AdvancedFilters
        filters={filters}
        severityCounts={severityCounts}
        onToggleSeverity={onToggleSeverity}
        onSetThirdParty={onSetThirdParty}
        onSetFilePath={onSetFilePath}
      />

      {/* Results count */}
      <div className="text-sm text-gray-400">
        {hasActiveFilters ? (
          <>
            Showing <span className="text-white font-medium">{filteredCount}</span> of{' '}
            <span className="text-white font-medium">{totalCount}</span> vulnerabilities
          </>
        ) : (
          <>
            <span className="text-white font-medium">{totalCount}</span> vulnerabilities
          </>
        )}
      </div>
    </div>
  );
}
