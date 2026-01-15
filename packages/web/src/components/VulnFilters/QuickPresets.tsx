import { useState } from 'react';
import { Plus, X, Save } from 'lucide-react';
import type { FilterPreset } from '../../hooks/useVulnFilters';
import type { SavedPreset } from '../../hooks/useFilterPresets';
import type { VulnFilters } from '../../types';

interface QuickPresetsProps {
  defaultPresets: FilterPreset[];
  savedPresets: SavedPreset[];
  activePresetId: string | null;
  onSelectPreset: (preset: FilterPreset | SavedPreset) => void;
  onSavePreset: (name: string, filters: Partial<VulnFilters>, icon?: string) => void;
  onDeletePreset: (id: string) => void;
  currentFilters: VulnFilters;
  hasActiveFilters: boolean;
}

const PRESET_ICONS = ['⭐', '🎯', '🔒', '💡', '🚀', '📌', '🔖', '💎'];

export default function QuickPresets({
  defaultPresets,
  savedPresets,
  activePresetId,
  onSelectPreset,
  onSavePreset,
  onDeletePreset,
  currentFilters,
  hasActiveFilters,
}: QuickPresetsProps) {
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [newPresetName, setNewPresetName] = useState('');
  const [selectedIcon, setSelectedIcon] = useState(PRESET_ICONS[0]);

  const handleSave = () => {
    if (newPresetName.trim()) {
      onSavePreset(newPresetName.trim(), currentFilters, selectedIcon);
      setNewPresetName('');
      setShowSaveModal(false);
    }
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-sm text-gray-400 mr-1">Quick Filters:</span>

      {/* Default presets */}
      {defaultPresets.map((preset) => (
        <button
          key={preset.id}
          onClick={() => onSelectPreset(preset)}
          className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors flex items-center gap-1.5 ${
            activePresetId === preset.id
              ? 'bg-arc-purple text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          {preset.icon && <span>{preset.icon}</span>}
          {preset.name}
        </button>
      ))}

      {/* Saved presets */}
      {savedPresets.map((preset) => (
        <div key={preset.id} className="relative group">
          <button
            onClick={() => onSelectPreset(preset)}
            className={`px-3 py-1.5 rounded-full text-sm font-medium transition-colors flex items-center gap-1.5 ${
              activePresetId === preset.id
                ? 'bg-arc-purple text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            {preset.icon && <span>{preset.icon}</span>}
            {preset.name}
          </button>
          {/* Delete button on hover */}
          <button
            onClick={(e) => {
              e.stopPropagation();
              onDeletePreset(preset.id);
            }}
            className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full text-white opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center"
            aria-label={`Delete ${preset.name}`}
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}

      {/* Save current filter button */}
      {hasActiveFilters && (
        <button
          onClick={() => setShowSaveModal(true)}
          className="px-3 py-1.5 rounded-full text-sm font-medium bg-gray-700/50 border border-dashed border-gray-500 text-gray-400 hover:border-arc-purple hover:text-arc-purple transition-colors flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          Save Filter
        </button>
      )}

      {/* Save Modal */}
      {showSaveModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-80 border border-gray-700">
            <h3 className="text-lg font-semibold mb-4">Save Filter Preset</h3>

            <div className="mb-4">
              <label className="block text-sm text-gray-400 mb-1">Name</label>
              <input
                type="text"
                value={newPresetName}
                onChange={(e) => setNewPresetName(e.target.value)}
                placeholder="My custom filter"
                className="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white"
                autoFocus
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm text-gray-400 mb-2">Icon</label>
              <div className="flex gap-2 flex-wrap">
                {PRESET_ICONS.map((icon) => (
                  <button
                    key={icon}
                    onClick={() => setSelectedIcon(icon)}
                    className={`w-8 h-8 rounded flex items-center justify-center text-lg ${
                      selectedIcon === icon
                        ? 'bg-arc-purple'
                        : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                  >
                    {icon}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => setShowSaveModal(false)}
                className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={!newPresetName.trim()}
                className="flex-1 px-4 py-2 bg-arc-purple hover:bg-arc-purple/80 rounded text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                <Save className="w-4 h-4" />
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
