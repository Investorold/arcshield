import { useState, useEffect, useCallback } from 'react';

const API_BASE = '/api';

interface GitHubUser {
  id: number;
  login: string;
  avatar_url: string;
  name: string;
}

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
  description: string | null;
  language: string | null;
  updated_at: string;
}

export function useGitHubAuth() {
  const [sessionId, setSessionId] = useState<string | null>(() => {
    return localStorage.getItem('arcshield_session');
  });
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Check session on mount and when sessionId changes
  useEffect(() => {
    if (sessionId) {
      checkSession(sessionId);
    }
  }, [sessionId]);

  const checkSession = async (sid: string) => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE}/auth/session/${sid}`);

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        localStorage.setItem('arcshield_session', sid);
      } else {
        // Invalid session
        setSessionId(null);
        setUser(null);
        localStorage.removeItem('arcshield_session');
      }
    } catch (err) {
      console.error('Session check error:', err);
    } finally {
      setLoading(false);
    }
  };

  const login = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_BASE}/auth/github`);
      const { url } = await response.json();

      // Redirect to GitHub
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setLoading(false);
    }
  };

  const handleCallback = useCallback((newSessionId: string) => {
    setSessionId(newSessionId);
    localStorage.setItem('arcshield_session', newSessionId);
  }, []);

  const logout = async () => {
    if (sessionId) {
      try {
        await fetch(`${API_BASE}/auth/logout/${sessionId}`, { method: 'POST' });
      } catch {
        // Ignore logout errors
      }
    }
    setSessionId(null);
    setUser(null);
    localStorage.removeItem('arcshield_session');
  };

  return {
    sessionId,
    user,
    loading,
    error,
    isLoggedIn: !!user,
    login,
    logout,
    handleCallback,
  };
}

export function useGitHubRepos(sessionId: string | null) {
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (sessionId) {
      fetchRepos();
    } else {
      setRepos([]);
    }
  }, [sessionId]);

  const fetchRepos = async () => {
    if (!sessionId) return;

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_BASE}/auth/repos/${sessionId}`);

      if (!response.ok) {
        throw new Error('Failed to fetch repositories');
      }

      const data = await response.json();
      setRepos(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch repos');
    } finally {
      setLoading(false);
    }
  };

  return { repos, loading, error, refresh: fetchRepos };
}

export function useScanRepo() {
  const [status, setStatus] = useState<{
    id: string;
    status: 'pending' | 'running' | 'completed' | 'failed';
    message?: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scanRepo = async (
    sessionId: string,
    repoFullName: string,
    model = 'haiku',
    provider = 'anthropic'
  ) => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_BASE}/scans/repo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, repoFullName, model, provider }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to start scan');
      }

      const data = await response.json();
      setStatus(data);

      // Poll for status
      pollStatus(data.id);

      return data;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      return null;
    } finally {
      setLoading(false);
    }
  };

  const pollStatus = async (scanId: string) => {
    const poll = async () => {
      try {
        const response = await fetch(`${API_BASE}/scans/${scanId}/status`);
        if (response.ok) {
          const data = await response.json();
          setStatus(data);

          if (data.status === 'pending' || data.status === 'running') {
            setTimeout(poll, 2000);
          }
        }
      } catch {
        // Ignore polling errors
      }
    };

    poll();
  };

  const reset = () => {
    setStatus(null);
    setError(null);
  };

  return { scanRepo, status, loading, error, reset };
}
