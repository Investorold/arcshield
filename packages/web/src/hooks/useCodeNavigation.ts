import { useEffect, useCallback } from 'react';
import type { Vulnerability, ArcVulnerability } from '../types';

type VulnItem = Vulnerability | ArcVulnerability;

interface UseCodeNavigationOptions {
  vulnerabilities: VulnItem[];
  selectedVuln: VulnItem | null;
  onSelectVuln: (vuln: VulnItem | null) => void;
  enabled?: boolean;
}

export function useCodeNavigation({
  vulnerabilities,
  selectedVuln,
  onSelectVuln,
  enabled = true,
}: UseCodeNavigationOptions) {
  const currentIndex = selectedVuln
    ? vulnerabilities.findIndex((v) => v.id === selectedVuln.id)
    : -1;

  const goToNext = useCallback(() => {
    if (vulnerabilities.length === 0) return;

    if (currentIndex === -1) {
      // No selection, go to first
      onSelectVuln(vulnerabilities[0]);
    } else if (currentIndex < vulnerabilities.length - 1) {
      onSelectVuln(vulnerabilities[currentIndex + 1]);
    }
  }, [vulnerabilities, currentIndex, onSelectVuln]);

  const goToPrev = useCallback(() => {
    if (vulnerabilities.length === 0) return;

    if (currentIndex === -1) {
      // No selection, go to last
      onSelectVuln(vulnerabilities[vulnerabilities.length - 1]);
    } else if (currentIndex > 0) {
      onSelectVuln(vulnerabilities[currentIndex - 1]);
    }
  }, [vulnerabilities, currentIndex, onSelectVuln]);

  const goToFirst = useCallback(() => {
    if (vulnerabilities.length > 0) {
      onSelectVuln(vulnerabilities[0]);
    }
  }, [vulnerabilities, onSelectVuln]);

  const goToLast = useCallback(() => {
    if (vulnerabilities.length > 0) {
      onSelectVuln(vulnerabilities[vulnerabilities.length - 1]);
    }
  }, [vulnerabilities, onSelectVuln]);

  const clearSelection = useCallback(() => {
    onSelectVuln(null);
  }, [onSelectVuln]);

  // Keyboard shortcuts
  useEffect(() => {
    if (!enabled) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in an input
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      switch (e.key) {
        case 'j':
        case 'ArrowDown':
          if (!e.metaKey && !e.ctrlKey) {
            e.preventDefault();
            goToNext();
          }
          break;
        case 'k':
        case 'ArrowUp':
          if (!e.metaKey && !e.ctrlKey) {
            e.preventDefault();
            goToPrev();
          }
          break;
        case 'g':
          if (e.shiftKey) {
            // Shift+G = go to last
            e.preventDefault();
            goToLast();
          } else {
            // g = go to first (vim style: gg)
            e.preventDefault();
            goToFirst();
          }
          break;
        case 'Escape':
          e.preventDefault();
          clearSelection();
          break;
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [enabled, goToNext, goToPrev, goToFirst, goToLast, clearSelection]);

  return {
    goToNext,
    goToPrev,
    goToFirst,
    goToLast,
    clearSelection,
    currentIndex,
    hasNext: currentIndex < vulnerabilities.length - 1,
    hasPrev: currentIndex > 0,
  };
}
