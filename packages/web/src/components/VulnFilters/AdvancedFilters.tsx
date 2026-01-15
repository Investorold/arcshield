import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';
import type { Severity, VulnFilters } from '../../types';

interface AdvancedFiltersProps {
  filters: VulnFilters;
  severityCounts: Record<Severity, number>;
  onToggleSeverity: (severity: Severity) => void;
  onSetThirdParty: (value: boolean | null) => void;
  onSetFilePath: (path: string | null) => void;
}

const SEVERITIES: { key: Severity; label: string; color: string; bgColor: string }[] = [
  { key: 'critical', label: 'Critical', color: 'text-red-400', bgColor: 'bg-red-500/20' },
  { key: 'high', label: 'High', color: 'text-orange-400', bgColor: 'bg-orange-500/20' },
  { key: 'medium', label: 'Medium', color: 'text-yellow-400', bgColor: 'bg-yellow-500/20' },
  { key: 'low', label: 'Low', color: 'text-green-400', bgColor: 'bg-green-500/20' },
  { key: 'info', label: 'Info', color: 'text-gray-400', bgColor: 'bg-gray-500/20' },
];

export default function AdvancedFilters({
  filters,
  severityCounts,
  onToggleSeverity,
  onSetThirdParty,
  onSetFilePath,
}: AdvancedFiltersProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      {/* Toggle header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2 bg-gray-800 hover:bg-gray-700 transition-colors"
      >
        <span className="text-sm font-medium text-gray-300">Advanced Filters</span>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-gray-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-gray-400" />
        )}
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="p-4 bg-gray-800/50 space-y-4">
          {/* Severity checkboxes */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">Severity</label>
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.map(({ key, label, color, bgColor }) => (
                <label
                  key={key}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded cursor-pointer transition-colors ${
                    filters.severities.includes(key)
                      ? `${bgColor} ${color}`
                      : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={filters.severities.includes(key)}
                    onChange={() => onToggleSeverity(key)}
                    className="sr-only"
                  />
                  <span className="text-sm">{label}</span>
                  <span className="text-xs opacity-70">({severityCounts[key]})</span>
                </label>
              ))}
            </div>
          </div>

          {/* Code ownership filter */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">Code Ownership</label>
            <div className="flex gap-2">
              <button
                onClick={() => onSetThirdParty(null)}
                className={`px-3 py-1.5 rounded text-sm transition-colors ${
                  filters.isThirdParty === null
                    ? 'bg-arc-purple text-white'
                    : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                }`}
              >
                All Code
              </button>
              <button
                onClick={() => onSetThirdParty(false)}
                className={`px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-1.5 ${
                  filters.isThirdParty === false
                    ? 'bg-blue-500/20 text-blue-400'
                    : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                }`}
              >
                <span>🏠</span> My Code
              </button>
              <button
                onClick={() => onSetThirdParty(true)}
                className={`px-3 py-1.5 rounded text-sm transition-colors flex items-center gap-1.5 ${
                  filters.isThirdParty === true
                    ? 'bg-purple-500/20 text-purple-400'
                    : 'bg-gray-700 text-gray-400 hover:bg-gray-600'
                }`}
              >
                <span>📦</span> Dependencies
              </button>
            </div>
          </div>

          {/* File path filter */}
          <div>
            <label className="block text-sm text-gray-400 mb-2">File Path Contains</label>
            <input
              type="text"
              value={filters.filePath || ''}
              onChange={(e) => onSetFilePath(e.target.value || null)}
              placeholder="e.g., src/auth, api/users"
              className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm text-white placeholder-gray-500"
            />
          </div>
        </div>
      )}
    </div>
  );
}
