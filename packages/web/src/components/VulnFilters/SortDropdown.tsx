import { useState, useRef, useEffect } from 'react';
import { ChevronDown, ArrowUp, ArrowDown } from 'lucide-react';
import type { SortConfig } from '../../types';

interface SortDropdownProps {
  sortConfig: SortConfig;
  onSortChange: (config: SortConfig) => void;
}

const SORT_OPTIONS: { field: SortConfig['field']; label: string }[] = [
  { field: 'severity', label: 'Severity' },
  { field: 'file', label: 'File Path' },
  { field: 'priority', label: 'Priority Score' },
  { field: 'lineNumber', label: 'Line Number' },
];

export default function SortDropdown({ sortConfig, onSortChange }: SortDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const currentOption = SORT_OPTIONS.find((opt) => opt.field === sortConfig.field);

  const handleFieldSelect = (field: SortConfig['field']) => {
    onSortChange({ ...sortConfig, field });
    setIsOpen(false);
  };

  const toggleOrder = () => {
    onSortChange({
      ...sortConfig,
      order: sortConfig.order === 'asc' ? 'desc' : 'asc',
    });
  };

  return (
    <div className="flex items-center gap-1" ref={dropdownRef}>
      {/* Sort field dropdown */}
      <div className="relative">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-l-lg border border-gray-600 text-sm transition-colors"
        >
          <span className="text-gray-400">Sort:</span>
          <span className="text-white">{currentOption?.label}</span>
          <ChevronDown className={`w-4 h-4 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {isOpen && (
          <div className="absolute top-full left-0 mt-1 w-40 bg-gray-800 border border-gray-700 rounded-lg shadow-lg overflow-hidden z-20">
            {SORT_OPTIONS.map((option) => (
              <button
                key={option.field}
                onClick={() => handleFieldSelect(option.field)}
                className={`w-full text-left px-3 py-2 text-sm transition-colors ${
                  sortConfig.field === option.field
                    ? 'bg-arc-purple/20 text-arc-purple'
                    : 'text-gray-300 hover:bg-gray-700'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Order toggle button */}
      <button
        onClick={toggleOrder}
        className="flex items-center justify-center w-10 h-10 bg-gray-700 hover:bg-gray-600 rounded-r-lg border border-l-0 border-gray-600 transition-colors"
        aria-label={`Sort ${sortConfig.order === 'asc' ? 'ascending' : 'descending'}`}
        title={sortConfig.order === 'asc' ? 'Ascending' : 'Descending'}
      >
        {sortConfig.order === 'asc' ? (
          <ArrowUp className="w-4 h-4 text-gray-300" />
        ) : (
          <ArrowDown className="w-4 h-4 text-gray-300" />
        )}
      </button>
    </div>
  );
}
