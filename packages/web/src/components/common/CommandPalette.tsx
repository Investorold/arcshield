import { useState, useEffect, useRef, useCallback } from 'react';
import { Search, X, AlertTriangle, Home, Package } from 'lucide-react';
import type { Severity } from '../../types';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onApplyFilter: (filter: CommandFilter) => void;
  recentSearches?: string[];
}

export interface CommandFilter {
  type: 'severity' | 'search' | 'file' | 'ownership' | 'cwe';
  value: string | Severity | boolean;
}

interface CommandOption {
  id: string;
  label: string;
  description: string;
  icon: React.ReactNode;
  filter: CommandFilter;
  keywords: string[];
}

const COMMANDS: CommandOption[] = [
  {
    id: 'severity-critical',
    label: 'severity:critical',
    description: 'Show only critical vulnerabilities',
    icon: <AlertTriangle className="w-4 h-4 text-red-400" />,
    filter: { type: 'severity', value: 'critical' },
    keywords: ['critical', 'severity', 'crit'],
  },
  {
    id: 'severity-high',
    label: 'severity:high',
    description: 'Show only high severity vulnerabilities',
    icon: <AlertTriangle className="w-4 h-4 text-orange-400" />,
    filter: { type: 'severity', value: 'high' },
    keywords: ['high', 'severity'],
  },
  {
    id: 'severity-medium',
    label: 'severity:medium',
    description: 'Show only medium severity vulnerabilities',
    icon: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    filter: { type: 'severity', value: 'medium' },
    keywords: ['medium', 'severity', 'med'],
  },
  {
    id: 'severity-low',
    label: 'severity:low',
    description: 'Show only low severity vulnerabilities',
    icon: <AlertTriangle className="w-4 h-4 text-green-400" />,
    filter: { type: 'severity', value: 'low' },
    keywords: ['low', 'severity'],
  },
  {
    id: 'ownership-mycode',
    label: 'is:first-party',
    description: 'Show only vulnerabilities in your code',
    icon: <Home className="w-4 h-4 text-blue-400" />,
    filter: { type: 'ownership', value: false },
    keywords: ['first', 'party', 'my', 'code', 'own'],
  },
  {
    id: 'ownership-deps',
    label: 'is:third-party',
    description: 'Show only vulnerabilities in dependencies',
    icon: <Package className="w-4 h-4 text-purple-400" />,
    filter: { type: 'ownership', value: true },
    keywords: ['third', 'party', 'deps', 'dependencies', 'node_modules'],
  },
];

export default function CommandPalette({
  isOpen,
  onClose,
  onApplyFilter,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  // Filter commands based on query
  const filteredCommands = query
    ? COMMANDS.filter(
        (cmd) =>
          cmd.label.toLowerCase().includes(query.toLowerCase()) ||
          cmd.keywords.some((kw) => kw.toLowerCase().includes(query.toLowerCase()))
      )
    : COMMANDS;

  // Check if query is a direct search (not matching any command)
  const isDirectSearch = query && filteredCommands.length === 0;

  // Reset state when opened
  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [isOpen]);

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (!isOpen) return;

      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setSelectedIndex((prev) =>
            prev < filteredCommands.length - 1 ? prev + 1 : prev
          );
          break;
        case 'ArrowUp':
          e.preventDefault();
          setSelectedIndex((prev) => (prev > 0 ? prev - 1 : prev));
          break;
        case 'Enter':
          e.preventDefault();
          if (isDirectSearch) {
            onApplyFilter({ type: 'search', value: query });
            onClose();
          } else if (filteredCommands[selectedIndex]) {
            onApplyFilter(filteredCommands[selectedIndex].filter);
            onClose();
          }
          break;
        case 'Escape':
          e.preventDefault();
          onClose();
          break;
      }
    },
    [isOpen, filteredCommands, selectedIndex, isDirectSearch, query, onApplyFilter, onClose]
  );

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  // Global Cmd+K listener
  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (!isOpen) {
          // This will be handled by parent
        }
      }
    };

    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => document.removeEventListener('keydown', handleGlobalKeyDown);
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-lg bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Search input */}
        <div className="flex items-center px-4 border-b border-gray-700">
          <Search className="w-5 h-5 text-gray-400" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Type a command or search..."
            className="flex-1 bg-transparent px-3 py-4 text-white placeholder-gray-500 focus:outline-none"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="p-1 hover:bg-gray-700 rounded"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          )}
        </div>

        {/* Commands list */}
        <div className="max-h-80 overflow-y-auto">
          {isDirectSearch ? (
            <button
              onClick={() => {
                onApplyFilter({ type: 'search', value: query });
                onClose();
              }}
              className="w-full flex items-center gap-3 px-4 py-3 bg-arc-purple/20 text-left"
            >
              <Search className="w-4 h-4 text-arc-purple" />
              <div>
                <div className="text-white">Search: "{query}"</div>
                <div className="text-sm text-gray-400">
                  Search vulnerabilities for this text
                </div>
              </div>
            </button>
          ) : (
            filteredCommands.map((cmd, index) => (
              <button
                key={cmd.id}
                onClick={() => {
                  onApplyFilter(cmd.filter);
                  onClose();
                }}
                className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors ${
                  index === selectedIndex
                    ? 'bg-gray-800'
                    : 'hover:bg-gray-800/50'
                }`}
              >
                {cmd.icon}
                <div className="flex-1">
                  <div className="text-white font-mono text-sm">{cmd.label}</div>
                  <div className="text-sm text-gray-400">{cmd.description}</div>
                </div>
                {index === selectedIndex && (
                  <span className="text-xs text-gray-500">Enter to select</span>
                )}
              </button>
            ))
          )}
        </div>

        {/* Footer hints */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-gray-700 bg-gray-800/50 text-xs text-gray-500">
          <div className="flex items-center gap-4">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>Esc Close</span>
          </div>
          <div>
            Tip: Type <code className="bg-gray-700 px-1 rounded">file:src/</code> to filter by path
          </div>
        </div>
      </div>
    </div>
  );
}
