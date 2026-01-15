import { useState, useCallback, useEffect } from 'react';
import type { VulnFilters } from '../types';

const STORAGE_KEY = 'arcshield-filter-presets';

export interface SavedPreset {
  id: string;
  name: string;
  icon: string;
  filters: Partial<VulnFilters>;
  createdAt: string;
}

interface UseFilterPresetsReturn {
  presets: SavedPreset[];
  savePreset: (name: string, filters: Partial<VulnFilters>, icon?: string) => void;
  deletePreset: (id: string) => void;
  updatePreset: (id: string, updates: Partial<SavedPreset>) => void;
}

export function useFilterPresets(): UseFilterPresetsReturn {
  const [presets, setPresets] = useState<SavedPreset[]>([]);

  // Load presets from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setPresets(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Failed to load filter presets:', error);
    }
  }, []);

  // Save presets to localStorage whenever they change
  const persistPresets = useCallback((newPresets: SavedPreset[]) => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newPresets));
      setPresets(newPresets);
    } catch (error) {
      console.error('Failed to save filter presets:', error);
    }
  }, []);

  const savePreset = useCallback((
    name: string,
    filters: Partial<VulnFilters>,
    icon: string = '⭐'
  ) => {
    const newPreset: SavedPreset = {
      id: `custom-${Date.now()}`,
      name,
      icon,
      filters,
      createdAt: new Date().toISOString(),
    };
    persistPresets([...presets, newPreset]);
  }, [presets, persistPresets]);

  const deletePreset = useCallback((id: string) => {
    persistPresets(presets.filter(p => p.id !== id));
  }, [presets, persistPresets]);

  const updatePreset = useCallback((id: string, updates: Partial<SavedPreset>) => {
    persistPresets(presets.map(p => p.id === id ? { ...p, ...updates } : p));
  }, [presets, persistPresets]);

  return {
    presets,
    savePreset,
    deletePreset,
    updatePreset,
  };
}
