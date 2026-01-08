import { useState, useRef, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useStartScan } from '../hooks/useScans';
import { useGitHubAuth, useGitHubRepos, useScanRepo } from '../hooks/useAuth';

type ScanType = 'github-connected' | 'github-url' | 'upload';

export default function Scan() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { scanGitHub, scanUpload, status: urlStatus, loading: urlLoading, error: urlError, reset: resetUrl } = useStartScan();
  const { sessionId, user, isLoggedIn, login, logout, handleCallback, loading: authLoading } = useGitHubAuth();
  const { repos, loading: reposLoading } = useGitHubRepos(sessionId);
  const { scanRepo, status: repoStatus, loading: repoLoading, error: repoError, reset: resetRepo } = useScanRepo();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [scanType, setScanType] = useState<ScanType>('github-connected');
  const [githubUrl, setGithubUrl] = useState('');
  const [selectedRepo, setSelectedRepo] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [model, setModel] = useState('haiku');
  const [provider, setProvider] = useState('anthropic');
  const [isDragging, setIsDragging] = useState(false);
  const [repoSearch, setRepoSearch] = useState('');

  // Handle OAuth callback
  useEffect(() => {
    const sessionParam = searchParams.get('session');
    const errorParam = searchParams.get('error');

    if (sessionParam) {
      handleCallback(sessionParam);
      setSearchParams({});
    }

    if (errorParam) {
      console.error('OAuth error:', errorParam);
      setSearchParams({});
    }
  }, [searchParams, handleCallback, setSearchParams]);

  // Combined status and loading
  const status = scanType === 'github-connected' ? repoStatus : urlStatus;
  const loading = scanType === 'github-connected' ? repoLoading : urlLoading;
  const error = scanType === 'github-connected' ? repoError : urlError;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (scanType === 'github-connected') {
      if (!selectedRepo || !sessionId) return;
      await scanRepo(sessionId, selectedRepo, model, provider);
    } else if (scanType === 'github-url') {
      if (!githubUrl.trim()) return;
      await scanGitHub(githubUrl, model, provider);
    } else {
      if (!selectedFile) return;
      await scanUpload(selectedFile, model, provider);
    }
  };

  const handleFileSelect = (file: File) => {
    if (file.name.endsWith('.zip') || file.type === 'application/zip') {
      setSelectedFile(file);
    } else {
      alert('Please upload a ZIP file');
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  };

  const handleViewReport = () => {
    if (status?.id) {
      navigate(`/report/${status.id}`);
    }
  };

  const handleNewScan = () => {
    resetUrl();
    resetRepo();
    setGithubUrl('');
    setSelectedFile(null);
    setSelectedRepo('');
  };

  // Filter repos by search
  const filteredRepos = repos.filter(repo =>
    repo.full_name.toLowerCase().includes(repoSearch.toLowerCase()) ||
    (repo.description?.toLowerCase().includes(repoSearch.toLowerCase()))
  );

  // Show status while scanning
  if (status) {
    return (
      <div>
        <h1 className="text-3xl font-bold mb-2">Security Scan</h1>
        <p className="text-gray-400 mb-8">Scanning your code for vulnerabilities</p>

        <div className="bg-gray-800 rounded-lg p-8 max-w-2xl">
          <div className="text-center">
            {status.status === 'pending' && (
              <>
                <div className="text-6xl mb-4">⏳</div>
                <h2 className="text-xl font-semibold">Initializing Scan</h2>
                <p className="text-gray-400 mt-2">{status.message || 'Preparing...'}</p>
              </>
            )}

            {status.status === 'running' && (
              <>
                <div className="text-6xl mb-4 animate-pulse">🔍</div>
                <h2 className="text-xl font-semibold">Scanning in Progress</h2>
                <p className="text-gray-400 mt-2">{status.message || 'Analyzing code...'}</p>
                <div className="mt-4 bg-gray-700 rounded-full h-2 overflow-hidden">
                  <div className="bg-arc-purple h-full animate-pulse" style={{ width: '60%' }} />
                </div>
                <p className="text-sm text-gray-500 mt-4">This may take 30-60 seconds</p>
              </>
            )}

            {status.status === 'completed' && (
              <>
                <div className="text-6xl mb-4">✅</div>
                <h2 className="text-xl font-semibold text-green-400">Scan Complete!</h2>
                <p className="text-gray-400 mt-2">Your security report is ready</p>
                <div className="mt-6 flex gap-4 justify-center">
                  <button
                    onClick={handleViewReport}
                    className="bg-arc-purple hover:bg-arc-purple/80 text-white px-6 py-2 rounded-lg transition-colors"
                  >
                    View Report
                  </button>
                  <button
                    onClick={handleNewScan}
                    className="bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors"
                  >
                    New Scan
                  </button>
                </div>
              </>
            )}

            {status.status === 'failed' && (
              <>
                <div className="text-6xl mb-4">❌</div>
                <h2 className="text-xl font-semibold text-red-400">Scan Failed</h2>
                <p className="text-gray-400 mt-2">{status.message || 'An error occurred'}</p>
                <button
                  onClick={handleNewScan}
                  className="mt-6 bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg transition-colors"
                >
                  Try Again
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-3xl font-bold mb-2">New Security Scan</h1>
      <p className="text-gray-400 mb-8">Scan any codebase for security vulnerabilities</p>

      <div className="bg-gray-800 rounded-lg p-6 max-w-2xl">
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4 text-red-400">
            {error}
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-2 mb-6">
          <button
            type="button"
            onClick={() => setScanType('github-connected')}
            className={`flex-1 py-3 px-4 rounded-lg font-medium transition-colors ${
              scanType === 'github-connected'
                ? 'bg-arc-purple text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            <span className="mr-2">🔗</span>
            My Repos
          </button>
          <button
            type="button"
            onClick={() => setScanType('github-url')}
            className={`flex-1 py-3 px-4 rounded-lg font-medium transition-colors ${
              scanType === 'github-url'
                ? 'bg-arc-purple text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            <span className="mr-2">🌐</span>
            Public URL
          </button>
          <button
            type="button"
            onClick={() => setScanType('upload')}
            className={`flex-1 py-3 px-4 rounded-lg font-medium transition-colors ${
              scanType === 'upload'
                ? 'bg-arc-purple text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            <span className="mr-2">📁</span>
            Upload
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {/* GitHub Connected Repos */}
          {scanType === 'github-connected' && (
            <div className="mb-6">
              {!isLoggedIn ? (
                <div className="text-center py-8">
                  <span className="text-5xl mb-4 block">🔐</span>
                  <h3 className="text-lg font-semibold mb-2">Connect Your GitHub</h3>
                  <p className="text-gray-400 mb-4">
                    Connect your GitHub account to scan your public and private repositories
                  </p>
                  <button
                    type="button"
                    onClick={login}
                    disabled={authLoading}
                    className="bg-gray-900 hover:bg-gray-950 border border-gray-600 text-white px-6 py-3 rounded-lg font-medium transition-colors inline-flex items-center gap-2"
                  >
                    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                    </svg>
                    {authLoading ? 'Connecting...' : 'Connect with GitHub'}
                  </button>
                </div>
              ) : (
                <>
                  {/* User info */}
                  <div className="flex items-center justify-between mb-4 p-3 bg-gray-700/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      <img
                        src={user?.avatar_url}
                        alt={user?.login}
                        className="w-10 h-10 rounded-full"
                      />
                      <div>
                        <p className="font-medium">{user?.name || user?.login}</p>
                        <p className="text-sm text-gray-400">@{user?.login}</p>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={logout}
                      className="text-sm text-gray-400 hover:text-white"
                    >
                      Disconnect
                    </button>
                  </div>

                  {/* Repo selector */}
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Select Repository
                  </label>

                  {/* Search */}
                  <input
                    type="text"
                    value={repoSearch}
                    onChange={(e) => setRepoSearch(e.target.value)}
                    placeholder="Search repositories..."
                    className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white placeholder-gray-400 focus:outline-none focus:border-arc-purple mb-2"
                  />

                  {/* Repo list */}
                  <div className="max-h-64 overflow-y-auto border border-gray-600 rounded-lg">
                    {reposLoading ? (
                      <div className="p-4 text-center text-gray-400">Loading repositories...</div>
                    ) : filteredRepos.length === 0 ? (
                      <div className="p-4 text-center text-gray-400">No repositories found</div>
                    ) : (
                      filteredRepos.map(repo => (
                        <button
                          key={repo.id}
                          type="button"
                          onClick={() => setSelectedRepo(repo.full_name)}
                          className={`w-full text-left p-3 border-b border-gray-700 last:border-0 transition-colors ${
                            selectedRepo === repo.full_name
                              ? 'bg-arc-purple/20'
                              : 'hover:bg-gray-700/50'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span>{repo.private ? '🔒' : '📂'}</span>
                              <span className="font-medium">{repo.name}</span>
                            </div>
                            {repo.language && (
                              <span className="text-xs bg-gray-600 px-2 py-0.5 rounded">
                                {repo.language}
                              </span>
                            )}
                          </div>
                          {repo.description && (
                            <p className="text-sm text-gray-400 mt-1 truncate">{repo.description}</p>
                          )}
                        </button>
                      ))
                    )}
                  </div>

                  {selectedRepo && (
                    <p className="text-sm text-green-400 mt-2">
                      Selected: {selectedRepo}
                    </p>
                  )}
                </>
              )}
            </div>
          )}

          {/* GitHub URL Input */}
          {scanType === 'github-url' && (
            <div className="mb-6">
              <label htmlFor="github-url" className="block text-sm font-medium text-gray-300 mb-2">
                GitHub Repository URL
              </label>
              <input
                type="text"
                id="github-url"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:border-arc-purple"
                required={scanType === 'github-url'}
              />
              <p className="text-xs text-gray-500 mt-1">
                Paste any public GitHub repository URL
              </p>
            </div>
          )}

          {/* File Upload */}
          {scanType === 'upload' && (
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Upload ZIP File
              </label>
              <div
                onDrop={handleDrop}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
                  isDragging
                    ? 'border-arc-purple bg-arc-purple/10'
                    : selectedFile
                    ? 'border-green-500 bg-green-500/10'
                    : 'border-gray-600 hover:border-gray-500'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleFileSelect(file);
                  }}
                />
                {selectedFile ? (
                  <>
                    <span className="text-4xl">📦</span>
                    <p className="mt-2 font-medium text-green-400">{selectedFile.name}</p>
                    <p className="text-sm text-gray-400">
                      {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                      className="mt-2 text-sm text-red-400 hover:underline"
                    >
                      Remove
                    </button>
                  </>
                ) : (
                  <>
                    <span className="text-4xl">📤</span>
                    <p className="mt-2 text-gray-300">Drag & drop your ZIP file here</p>
                    <p className="text-sm text-gray-500">or click to browse</p>
                  </>
                )}
              </div>
              <p className="text-xs text-gray-500 mt-1">
                ZIP your project folder and upload it (max 50MB)
              </p>
            </div>
          )}

          {/* Model Selection - Only show when input is provided */}
          {(scanType !== 'github-connected' || isLoggedIn) && (
            <div className="grid grid-cols-2 gap-4 mb-6">
              <div>
                <label htmlFor="provider" className="block text-sm font-medium text-gray-300 mb-2">
                  AI Provider
                </label>
                <select
                  id="provider"
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-arc-purple"
                >
                  <option value="anthropic">Anthropic (Claude)</option>
                  <option value="ollama">Ollama (Local)</option>
                </select>
              </div>

              <div>
                <label htmlFor="model" className="block text-sm font-medium text-gray-300 mb-2">
                  Model
                </label>
                <select
                  id="model"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-arc-purple"
                >
                  {provider === 'anthropic' ? (
                    <>
                      <option value="haiku">Haiku (Fast & Cheap)</option>
                      <option value="sonnet">Sonnet (Balanced)</option>
                      <option value="opus">Opus (Most Capable)</option>
                    </>
                  ) : (
                    <>
                      <option value="llama3">Llama 3</option>
                      <option value="mistral">Mistral</option>
                      <option value="codellama">CodeLlama</option>
                    </>
                  )}
                </select>
              </div>
            </div>
          )}

          {/* Features List */}
          {(scanType !== 'github-connected' || isLoggedIn) && (
            <div className="bg-gray-700/50 rounded-lg p-4 mb-6">
              <h3 className="text-sm font-medium text-gray-300 mb-2">Scan includes:</h3>
              <ul className="text-sm text-gray-400 space-y-1">
                <li>✓ Architecture assessment</li>
                <li>✓ STRIDE threat modeling</li>
                <li>✓ Vulnerability code review</li>
                <li>✓ Arc-specific security checks</li>
                <li>✓ Smart contract analysis (Solidity)</li>
              </ul>
            </div>
          )}

          {/* Submit Button */}
          {(scanType !== 'github-connected' || isLoggedIn) && (
            <button
              type="submit"
              disabled={
                loading ||
                (scanType === 'github-connected' && !selectedRepo) ||
                (scanType === 'github-url' && !githubUrl.trim()) ||
                (scanType === 'upload' && !selectedFile)
              }
              className="w-full bg-arc-purple hover:bg-arc-purple/80 disabled:bg-gray-600 disabled:cursor-not-allowed text-white py-3 rounded-lg font-medium transition-colors"
            >
              {loading ? 'Starting Scan...' : 'Start Security Scan'}
            </button>
          )}
        </form>
      </div>
    </div>
  );
}
