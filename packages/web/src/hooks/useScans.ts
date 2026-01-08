import { useState, useEffect, useCallback } from 'react';
import type { ScanReport } from '../types';

const API_BASE = '/api';

interface ScanListItem {
  id: string;
  timestamp: string;
  target: string;
  score: number;
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface ScanStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  message?: string;
}

export function useScans() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScans = useCallback(async (retries = 3) => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch(`${API_BASE}/scans`);
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
      setError(null);
    } catch (err) {
      // Retry on failure
      if (retries > 0) {
        setTimeout(() => fetchScans(retries - 1), 1000);
        return;
      }
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  return { scans, loading, error, refresh: fetchScans };
}

export function useScan(id: string | undefined) {
  const [scan, setScan] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      setLoading(false);
      return;
    }

    const fetchScan = async () => {
      try {
        setLoading(true);
        const response = await fetch(`${API_BASE}/scans/${id}`);
        if (!response.ok) throw new Error('Scan not found');
        const data = await response.json();
        setScan(data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
      } finally {
        setLoading(false);
      }
    };

    fetchScan();
  }, [id]);

  return { scan, loading, error };
}

export function useStartScan() {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pollStatus = async (scanId: string) => {
    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE}/scans/${scanId}/status`);
        if (response.ok) {
          const data = await response.json();
          setStatus(data);

          if (data.status === 'pending' || data.status === 'running') {
            setTimeout(poll, 2000); // Poll every 2 seconds
          }
        }
      } catch {
        // Ignore polling errors
      }
    };

    poll();
  };

  // Scan GitHub repository
  const scanGitHub = async (url: string, model = 'haiku', provider = 'anthropic') => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_BASE}/scans/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, model, provider }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to start scan');
      }

      const data = await response.json();
      setStatus(data);
      pollStatus(data.id);
      return data;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Scan uploaded ZIP file
  const scanUpload = async (file: File, model = 'haiku', provider = 'anthropic') => {
    try {
      setLoading(true);
      setError(null);

      const arrayBuffer = await file.arrayBuffer();

      const response = await fetch(`${API_BASE}/scans/upload`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Filename': file.name,
          'X-Model': model,
          'X-Provider': provider,
        },
        body: arrayBuffer,
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to start scan');
      }

      const data = await response.json();
      setStatus(data);
      pollStatus(data.id);
      return data;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      return null;
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setStatus(null);
    setError(null);
  };

  return { scanGitHub, scanUpload, status, loading, error, reset };
}
