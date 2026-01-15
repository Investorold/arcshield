import { useState, useEffect, useCallback } from 'react';
import { Check, CheckCircle } from 'lucide-react';
import type { Vulnerability, ArcVulnerability, Severity } from '../types';
import { useVulnFilters } from '../hooks/useVulnFilters';
import { usePagination } from '../hooks/usePagination';
import VulnFilterBar from './VulnFilters/VulnFilterBar';
import CommandPalette, { type CommandFilter } from './common/CommandPalette';
import Pagination from './common/Pagination';

interface VulnTableProps {
  vulnerabilities: (Vulnerability | ArcVulnerability)[];
  title?: string;
  showFilters?: boolean;
  pageSize?: number;
}

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', label: 'Critical' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', label: 'High' },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', label: 'Medium' },
  low: { color: 'text-green-500', bg: 'bg-green-500/10', label: 'Low' },
  info: { color: 'text-gray-500', bg: 'bg-gray-500/10', label: 'Info' },
};

// Component for the copy button
function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <button
      onClick={handleCopy}
      className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
        copied
          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
          : 'bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30'
      }`}
    >
      {copied ? <><Check className="w-4 h-4 inline mr-1" /> Copied!</> : label}
    </button>
  );
}

// Expandable row component
function VulnRow({ vuln }: { vuln: Vulnerability | ArcVulnerability }) {
  const [expanded, setExpanded] = useState(false);
  const config = SEVERITY_CONFIG[vuln.severity];

  // Generate a better AI Fix Prompt
  const generateAIPrompt = () => {
    const prompt = `I have a security vulnerability in my code that I need help fixing.

**Vulnerability Details:**
- Type: ${vuln.title}
- Severity: ${vuln.severity.toUpperCase()}
- Location: ${vuln.filePath}:${vuln.lineNumber}
- CWE: ${vuln.cweId || 'N/A'}

**Description:**
${vuln.description}

**Code with the issue:**
\`\`\`
${vuln.codeSnippet || 'See file at line ' + vuln.lineNumber}
\`\`\`

**Recommended Fix:**
${vuln.remediation || 'Review and fix the security issue'}

Please provide:
1. The fixed code
2. An explanation of what was wrong
3. How the fix prevents the vulnerability`;

    return prompt;
  };

  return (
    <>
      {/* Main row - clickable */}
      <tr
        onClick={() => setExpanded(!expanded)}
        className="hover:bg-gray-700/30 transition-colors cursor-pointer"
      >
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 rounded text-xs font-medium ${config.color} ${config.bg}`}>
              {config.label}
            </span>
            {/* Third-party indicator (OWASP/NIST SBOM) */}
            {vuln.isThirdParty && (
              <span className="px-1.5 py-0.5 rounded text-xs bg-purple-500/20 text-purple-400" title={`Source: ${vuln.thirdPartySource || 'dependency'}`}>
                📦
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-3 text-sm font-mono text-gray-300">{vuln.id}</td>
        <td className="px-4 py-3 text-sm text-white">{vuln.title}</td>
        <td className="px-4 py-3 text-sm text-gray-400 font-mono">
          {vuln.filePath}:{vuln.lineNumber}
        </td>
        <td className="px-4 py-3 text-sm text-gray-400">{vuln.cweId || '-'}</td>
        <td className="px-4 py-3 text-sm text-gray-500">
          {expanded ? '▲' : '▼'}
        </td>
      </tr>

      {/* Expanded details row */}
      {expanded && (
        <tr>
          <td colSpan={6} className="px-4 py-4 bg-gray-800/50">
            <div className="space-y-4">
              {/* Third-Party Info (OWASP/NIST SBOM) */}
              {vuln.isThirdParty && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-3 mb-4">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-purple-400 font-medium text-sm">📦 Third-Party Dependency</span>
                    <span className="text-xs bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded">
                      {vuln.dependencyType || 'dependency'}
                    </span>
                  </div>
                  <p className="text-xs text-purple-300">
                    Source: {vuln.thirdPartySource || 'node_modules'} •
                    Fix by updating the package or using a different version.
                  </p>
                </div>
              )}

              {/* Priority Score */}
              {vuln.priorityScore !== undefined && (
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-xs text-gray-500">Priority Score:</span>
                  <div className="flex items-center gap-1">
                    <div className="w-20 h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          vuln.priorityScore >= 70 ? 'bg-red-500' :
                          vuln.priorityScore >= 50 ? 'bg-orange-500' :
                          vuln.priorityScore >= 30 ? 'bg-yellow-500' : 'bg-green-500'
                        }`}
                        style={{ width: `${vuln.priorityScore}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400">{vuln.priorityScore}/100</span>
                  </div>
                </div>
              )}

              {/* Description */}
              <div>
                <h4 className="text-sm font-semibold text-gray-300 mb-1">Description</h4>
                <p className="text-sm text-gray-400">{vuln.description}</p>
              </div>

              {/* Code Snippet */}
              {vuln.codeSnippet && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-300 mb-1">Code</h4>
                  <pre className="bg-gray-900 rounded p-3 text-sm text-gray-300 overflow-x-auto font-mono">
                    {vuln.codeSnippet}
                  </pre>
                </div>
              )}

              {/* How to Fix */}
              {vuln.remediation && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-300 mb-1">How to Fix</h4>
                  <p className="text-sm text-gray-400">{vuln.remediation}</p>
                </div>
              )}

              {/* AI Fix Prompt Section */}
              <div className="border-t border-gray-700 pt-4 mt-4">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-purple-400">
                    🤖 AI Fix Prompt
                  </h4>
                  <CopyButton text={generateAIPrompt()} label="Copy Prompt" />
                </div>
                <p className="text-xs text-gray-500 mb-2">
                  Copy this prompt and paste it into ChatGPT, Claude, or your AI assistant to get help fixing this issue.
                </p>
                <div className="bg-gray-900/80 border border-purple-500/20 rounded p-3 max-h-32 overflow-y-auto">
                  <pre className="text-xs text-gray-400 whitespace-pre-wrap font-mono">
                    {generateAIPrompt().substring(0, 300)}...
                  </pre>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function VulnTable({
  vulnerabilities,
  title = 'Vulnerabilities',
  showFilters = true,
  pageSize: initialPageSize = 25,
}: VulnTableProps) {
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  // Filtering hook
  const {
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
  } = useVulnFilters(vulnerabilities);

  // Pagination hook
  const {
    currentPage,
    pageSize,
    totalPages,
    paginatedItems,
    goToPage,
    setPageSize,
  } = usePagination(filteredVulns, { initialPageSize });

  // Global Cmd+K listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(true);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Handle command palette filter
  const handleCommandFilter = useCallback((filter: CommandFilter) => {
    switch (filter.type) {
      case 'severity':
        setSeverities([filter.value as Severity]);
        break;
      case 'search':
        setSearch(filter.value as string);
        break;
      case 'ownership':
        setIsThirdParty(filter.value as boolean);
        break;
      case 'file':
        setFilePath(filter.value as string);
        break;
    }
  }, [setSeverities, setSearch, setIsThirdParty, setFilePath]);

  // Empty state (no vulnerabilities at all)
  if (vulnerabilities.length === 0) {
    return (
      <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6">
        <h3 className="text-lg font-semibold mb-4">{title}</h3>
        <div className="flex items-center justify-center py-8 bg-green-900/10 rounded-lg border border-green-500/20">
          <div className="text-center">
            <CheckCircle className="w-12 h-12 text-green-400 mx-auto mb-2" aria-hidden="true" />
            <p className="text-green-400 font-medium">No vulnerabilities found</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-gray-800 rounded-lg overflow-hidden">
      {/* Header with title */}
      <div className="p-4 border-b border-gray-700">
        <h3 className="text-lg font-semibold">{title}</h3>
      </div>

      {/* Filter Bar */}
      {showFilters && (
        <div className="p-4 border-b border-gray-700 bg-gray-800/50">
          <VulnFilterBar
            filters={filters}
            sortConfig={sortConfig}
            severityCounts={severityCounts}
            totalCount={totalCount}
            filteredCount={filteredCount}
            hasActiveFilters={hasActiveFilters}
            onSearchChange={setSearch}
            onToggleSeverity={toggleSeverity}
            onSetThirdParty={setIsThirdParty}
            onSetFilePath={setFilePath}
            onSortChange={setSort}
            onApplyPreset={applyPreset}
            onResetFilters={resetFilters}
            onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          />
        </div>
      )}

      {/* Table or empty filtered state */}
      {filteredCount === 0 ? (
        <div className="p-8 text-center">
          <p className="text-gray-400 mb-4">No vulnerabilities match your filters.</p>
          <button
            onClick={resetFilters}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white text-sm"
          >
            Clear Filters
          </button>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-700/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">ID</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Title</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Location</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">CWE</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase w-8"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {paginatedItems.map((vuln) => (
                  <VulnRow key={vuln.id} vuln={vuln} />
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              pageSize={pageSize}
              totalItems={filteredCount}
              onPageChange={goToPage}
              onPageSizeChange={setPageSize}
            />
          )}
        </>
      )}

      {/* Command Palette */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onApplyFilter={handleCommandFilter}
      />
    </div>
  );
}
