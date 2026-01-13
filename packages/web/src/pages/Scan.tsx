import { useState, useRef, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useStartScan } from '../hooks/useScans';
import { useGitHubAuth, useGitHubRepos, useScanRepo } from '../hooks/useAuth';

declare global {
  interface Window {
    ethereum?: {
      request: (args: { method: string; params?: any[] }) => Promise<any>;
      on?: (event: string, callback: (...args: any[]) => void) => void;
    };
  }
}

type ScanType = 'github-connected' | 'github-url' | 'upload';
type ScanTier = 'free' | 'trial' | 'paid';

export default function Scan() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { scanGitHub, scanUpload, status: urlStatus, loading: urlLoading, error: urlError, reset: resetUrl } = useStartScan();
  const { sessionId, user, isLoggedIn, login, logout, handleCallback, loading: authLoading } = useGitHubAuth();
  const { repos, loading: reposLoading } = useGitHubRepos(sessionId);
  const { scanRepo, status: repoStatus, loading: repoLoading, error: repoError, reset: resetRepo } = useScanRepo();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [scanType, setScanType] = useState<ScanType>('github-url');
  const [scanTier, setScanTier] = useState<ScanTier>('free');
  const [githubUrl, setGithubUrl] = useState('');
  const [selectedRepo, setSelectedRepo] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [model, setModel] = useState('haiku');
  const [isDragging, setIsDragging] = useState(false);
  const [repoSearch, setRepoSearch] = useState('');
  const [walletAddress, setWalletAddress] = useState('');
  const [walletConnected, setWalletConnected] = useState(false);
  const [trialStatus, setTrialStatus] = useState<{ hasUsedTrial: boolean; loading: boolean }>({ hasUsedTrial: false, loading: false });
  const [paymentState, setPaymentState] = useState<{
    paymentId?: string;
    status: 'idle' | 'awaiting_payment' | 'confirming' | 'confirmed' | 'error';
    treasuryAddress?: string;
    amount?: number;
    error?: string;
    timeRemaining?: number;
  }>({ status: 'idle' });
  const [txHash, setTxHash] = useState('');

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

  // Connect wallet function
  const connectWallet = async () => {
    if (typeof window.ethereum === 'undefined') {
      alert('No wallet detected');
      return;
    }
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      if (accounts && accounts.length > 0) {
        setWalletAddress(accounts[0]);
        setWalletConnected(true);
      }
    } catch (err: any) {
      if (err.code !== 4001) { // User rejected
        console.error('Wallet connection error:', err);
      }
    }
  };

  // Disconnect wallet
  const disconnectWallet = () => {
    setWalletAddress('');
    setWalletConnected(false);
    setTrialStatus({ hasUsedTrial: false, loading: false });
  };

  // Check for existing wallet connection on mount
  useEffect(() => {
    if (typeof window.ethereum !== 'undefined') {
      window.ethereum.request({ method: 'eth_accounts' })
        .then((accounts: string[]) => {
          if (accounts && accounts.length > 0) {
            setWalletAddress(accounts[0]);
            setWalletConnected(true);
          }
        })
        .catch(() => {});

      // Listen for account changes
      window.ethereum.on?.('accountsChanged', (accounts: string[]) => {
        if (accounts.length > 0) {
          setWalletAddress(accounts[0]);
          setWalletConnected(true);
        } else {
          disconnectWallet();
        }
      });
    }
  }, []);

  // Check trial status when wallet address changes
  useEffect(() => {
    if (walletAddress && walletAddress.length >= 10) {
      setTrialStatus({ hasUsedTrial: false, loading: true });
      fetch(`/api/wallet/${walletAddress}/trial`)
        .then(res => res.json())
        .then(data => {
          setTrialStatus({ hasUsedTrial: data.hasUsedTrial, loading: false });
        })
        .catch(() => {
          setTrialStatus({ hasUsedTrial: false, loading: false });
        });
    }
  }, [walletAddress]);

  // Get target URL/repo based on scan type
  const getTargetUrl = () => {
    if (scanType === 'github-connected' && selectedRepo) {
      return `https://github.com/${selectedRepo}`;
    }
    return githubUrl;
  };

  // Create payment for paid tier
  const createPayment = async () => {
    const targetUrl = getTargetUrl();
    if (!targetUrl || !walletAddress) return;

    try {
      const response = await fetch('/api/payments/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ walletAddress, repoUrl: targetUrl }),
      });
      const data = await response.json();

      if (data.error) {
        setPaymentState({ status: 'error', error: data.error });
        return;
      }

      setPaymentState({
        status: 'awaiting_payment',
        paymentId: data.paymentId,
        treasuryAddress: data.treasuryAddress,
        amount: data.amount,
        timeRemaining: data.expiresIn,
      });
    } catch (err) {
      setPaymentState({ status: 'error', error: 'Failed to create payment' });
    }
  };

  // Confirm payment with transaction hash
  const confirmPayment = async () => {
    if (!paymentState.paymentId || !txHash) return;

    setPaymentState(prev => ({ ...prev, status: 'confirming' }));

    try {
      const response = await fetch(`/api/payments/${paymentState.paymentId}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ txHash }),
      });
      const data = await response.json();

      if (data.error) {
        setPaymentState(prev => ({
          ...prev,
          status: 'awaiting_payment',
          error: data.message || data.error
        }));
        return;
      }

      setPaymentState(prev => ({ ...prev, status: 'confirmed', error: undefined }));
    } catch (err) {
      setPaymentState(prev => ({ ...prev, status: 'awaiting_payment', error: 'Verification failed' }));
    }
  };

  // Report canceled transaction
  const reportCanceled = async () => {
    if (!paymentState.paymentId) return;

    try {
      await fetch(`/api/payments/${paymentState.paymentId}/canceled`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'user_rejected' }),
      });
    } catch (err) {
      // Silent fail - this is just analytics
    }
  };

  // Start paid scan after payment confirmed
  const startPaidScan = async () => {
    if (!paymentState.paymentId) return;

    try {
      const response = await fetch('/api/scans/paid', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ paymentId: paymentState.paymentId, model }),
      });
      const data = await response.json();

      if (data.error) {
        alert(data.message || data.error);
        return;
      }

      if (data.id) {
        navigate(`/report/${data.id}`);
      }
    } catch (err) {
      console.error('Paid scan error:', err);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const targetUrl = getTargetUrl();

    // Free tier
    if (scanTier === 'free') {
      if (scanType === 'upload' && selectedFile) {
        await scanUpload(selectedFile, model, 'anthropic');
        return;
      }
      if (!targetUrl) return;

      try {
        const response = await fetch('/api/scans/free', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
        });
        const data = await response.json();
        if (data.id) {
          navigate(`/report/${data.id}`);
        }
      } catch (err) {
        console.error('Free scan error:', err);
      }
      return;
    }

    // Trial tier
    if (scanTier === 'trial') {
      if (!targetUrl || !walletAddress) return;

      try {
        const response = await fetch('/api/scans/trial', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl, walletAddress, model }),
        });
        const data = await response.json();
        if (data.error) {
          alert(data.message || data.error);
          return;
        }
        if (data.id) {
          navigate(`/report/${data.id}`);
        }
      } catch (err) {
        console.error('Trial scan error:', err);
      }
      return;
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
    setPaymentState({ status: 'idle' });
    setTxHash('');
  };

  // Filter repos by search
  const filteredRepos = repos.filter(repo =>
    repo.full_name.toLowerCase().includes(repoSearch.toLowerCase())
  );

  // Check if can submit
  const canSubmit = () => {
    if (loading) return false;
    if (scanType === 'github-connected' && !selectedRepo) return false;
    if (scanType === 'github-url' && !githubUrl.trim()) return false;
    if (scanType === 'upload' && !selectedFile) return false;
    if (scanTier === 'trial' && (!walletConnected || trialStatus.hasUsedTrial)) return false;
    if (scanTier === 'paid') return false; // Paid uses separate flow
    return true;
  };

  // Show status while scanning
  if (status) {
    return (
      <div className="max-w-xl mx-auto">
        <div className="bg-gray-800 rounded-lg p-8">
          <div className="text-center">
            {status.status === 'pending' && (
              <>
                <div className="text-5xl mb-4">⏳</div>
                <h2 className="text-xl font-semibold">Initializing</h2>
                <p className="text-gray-400 mt-2">{status.message || 'Preparing...'}</p>
              </>
            )}

            {status.status === 'running' && (
              <>
                <div className="text-5xl mb-4 animate-pulse">🔍</div>
                <h2 className="text-xl font-semibold">Scanning</h2>
                <p className="text-gray-400 mt-2">{status.message || 'Analyzing...'}</p>
                <div className="mt-4 bg-gray-700 rounded-full h-2 overflow-hidden">
                  <div className="bg-arc-purple h-full animate-pulse" style={{ width: '60%' }} />
                </div>
              </>
            )}

            {status.status === 'completed' && (
              <>
                <div className="text-5xl mb-4">✅</div>
                <h2 className="text-xl font-semibold text-green-400">Complete</h2>
                <div className="mt-6 flex gap-3 justify-center">
                  <button onClick={handleViewReport} className="bg-arc-purple hover:bg-arc-purple/80 text-white px-6 py-2 rounded-lg">
                    View Report
                  </button>
                  <button onClick={handleNewScan} className="bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg">
                    New Scan
                  </button>
                </div>
              </>
            )}

            {status.status === 'failed' && (
              <>
                <div className="text-5xl mb-4">❌</div>
                <h2 className="text-xl font-semibold text-red-400">Failed</h2>
                <p className="text-gray-400 mt-2">{status.message}</p>
                <button onClick={handleNewScan} className="mt-6 bg-gray-700 hover:bg-gray-600 text-white px-6 py-2 rounded-lg">
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
    <div className="max-w-xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">New Scan</h1>

      <div className="bg-gray-800 rounded-lg p-5">
        {error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 mb-4 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Source Tabs */}
        <div className="flex gap-2 mb-5">
          <button
            type="button"
            onClick={() => setScanType('github-connected')}
            className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium ${
              scanType === 'github-connected' ? 'bg-arc-purple text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            🔗 My Repos
          </button>
          <button
            type="button"
            onClick={() => setScanType('github-url')}
            className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium ${
              scanType === 'github-url' ? 'bg-arc-purple text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            🌐 Public URL
          </button>
          <button
            type="button"
            onClick={() => setScanType('upload')}
            className={`flex-1 py-2 px-3 rounded-lg text-sm font-medium ${
              scanType === 'upload' ? 'bg-arc-purple text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            📁 Upload
          </button>
        </div>

        {/* My Repos - GitHub Connected */}
        {scanType === 'github-connected' && (
          <div className="mb-5">
            {!isLoggedIn ? (
              <div className="text-center py-6">
                <button
                  type="button"
                  onClick={login}
                  disabled={authLoading}
                  className="bg-gray-900 hover:bg-black border border-gray-600 text-white px-5 py-2 rounded-lg inline-flex items-center gap-2"
                >
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                  </svg>
                  {authLoading ? 'Connecting...' : 'Connect GitHub'}
                </button>
              </div>
            ) : (
              <>
                <div className="flex items-center justify-between mb-3 p-2 bg-gray-700/50 rounded-lg">
                  <div className="flex items-center gap-2">
                    <img src={user?.avatar_url} alt="" className="w-8 h-8 rounded-full" />
                    <span className="text-sm">@{user?.login}</span>
                  </div>
                  <button type="button" onClick={logout} className="text-xs text-gray-400 hover:text-white">
                    Disconnect
                  </button>
                </div>

                <input
                  type="text"
                  value={repoSearch}
                  onChange={(e) => setRepoSearch(e.target.value)}
                  placeholder="Search repos..."
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white mb-2"
                />

                <div className="max-h-48 overflow-y-auto border border-gray-600 rounded-lg">
                  {reposLoading ? (
                    <div className="p-3 text-center text-gray-400 text-sm">Loading...</div>
                  ) : filteredRepos.length === 0 ? (
                    <div className="p-3 text-center text-gray-400 text-sm">No repos found</div>
                  ) : (
                    filteredRepos.slice(0, 20).map(repo => (
                      <button
                        key={repo.id}
                        type="button"
                        onClick={() => setSelectedRepo(repo.full_name)}
                        className={`w-full text-left p-2 text-sm border-b border-gray-700 last:border-0 ${
                          selectedRepo === repo.full_name ? 'bg-arc-purple/20' : 'hover:bg-gray-700/50'
                        }`}
                      >
                        <span>{repo.private ? '🔒' : '📂'} {repo.name}</span>
                      </button>
                    ))
                  )}
                </div>

                {selectedRepo && (
                  <p className="text-xs text-green-400 mt-2">Selected: {selectedRepo}</p>
                )}
              </>
            )}
          </div>
        )}

        {/* Public URL */}
        {scanType === 'github-url' && (
          <div className="mb-5">
            <input
              type="text"
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400"
            />
          </div>
        )}

        {/* File Upload */}
        {scanType === 'upload' && (
          <div className="mb-5">
            <div
              onDrop={handleDrop}
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={() => setIsDragging(false)}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer ${
                isDragging ? 'border-arc-purple bg-arc-purple/10' :
                selectedFile ? 'border-green-500 bg-green-500/10' : 'border-gray-600 hover:border-gray-500'
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
                  <p className="font-medium text-green-400">📦 {selectedFile.name}</p>
                  <p className="text-xs text-gray-400 mt-1">{(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); setSelectedFile(null); }}
                    className="text-xs text-red-400 mt-2"
                  >
                    Remove
                  </button>
                </>
              ) : (
                <>
                  <p className="text-gray-300">📤 Drop ZIP file here</p>
                  <p className="text-xs text-gray-500 mt-1">or click to browse</p>
                </>
              )}
            </div>
          </div>
        )}

        {/* Scan Tier */}
        <div className="grid grid-cols-3 gap-2 mb-5">
          <button
            type="button"
            onClick={() => setScanTier('free')}
            className={`p-3 rounded-lg border-2 text-center ${
              scanTier === 'free' ? 'border-green-500 bg-green-500/10' : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <div className="text-green-400 font-bold">FREE</div>
            <div className="text-xs text-gray-400">91 rules</div>
          </button>

          <button
            type="button"
            onClick={() => setScanTier('trial')}
            disabled={trialStatus.hasUsedTrial}
            className={`p-3 rounded-lg border-2 text-center ${
              scanTier === 'trial' ? 'border-arc-purple bg-arc-purple/10' :
              trialStatus.hasUsedTrial ? 'border-gray-700 opacity-50' : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <div className="text-arc-purple font-bold">TRIAL</div>
            <div className="text-xs text-gray-400">{trialStatus.hasUsedTrial ? 'Used' : 'AI scan'}</div>
          </button>

          <button
            type="button"
            onClick={() => setScanTier('paid')}
            className={`p-3 rounded-lg border-2 text-center ${
              scanTier === 'paid' ? 'border-yellow-500 bg-yellow-500/10' : 'border-gray-600 hover:border-gray-500'
            }`}
          >
            <div className="text-yellow-400 font-bold">$0.15</div>
            <div className="text-xs text-gray-400">USDC</div>
          </button>
        </div>

        {/* Wallet Connection for Trial/Paid */}
        {(scanTier === 'trial' || scanTier === 'paid') && (
          <div className="mb-5">
            {!walletConnected ? (
              <button
                type="button"
                onClick={connectWallet}
                className="w-full bg-gray-700 hover:bg-gray-600 border border-gray-500 text-white py-3 rounded-lg font-medium flex items-center justify-center gap-2"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                </svg>
                Connect Wallet
              </button>
            ) : (
              <div className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-sm font-mono">{walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}</span>
                </div>
                <button
                  type="button"
                  onClick={disconnectWallet}
                  className="text-xs text-gray-400 hover:text-white"
                >
                  Disconnect
                </button>
              </div>
            )}
            {scanTier === 'trial' && walletConnected && !trialStatus.loading && (
              <p className={`text-xs mt-2 ${trialStatus.hasUsedTrial ? 'text-red-400' : 'text-green-400'}`}>
                {trialStatus.hasUsedTrial ? 'Trial already used' : 'Trial available'}
              </p>
            )}
          </div>
        )}

        {/* Payment Flow */}
        {scanTier === 'paid' && (
          <div className="mb-5">
            {paymentState.status === 'idle' && (
              <button
                type="button"
                onClick={createPayment}
                disabled={!getTargetUrl() || !walletConnected}
                className="w-full bg-yellow-500 hover:bg-yellow-600 disabled:bg-gray-600 text-black font-medium py-3 rounded-lg"
              >
                Create Payment
              </button>
            )}

            {(paymentState.status === 'awaiting_payment' || paymentState.status === 'confirming') && (
              <div className="space-y-3">
                <div className="bg-gray-700 rounded-lg p-3 text-sm">
                  <div className="flex justify-between mb-2">
                    <span className="text-gray-400">Amount</span>
                    <span>{paymentState.amount} USDC</span>
                  </div>
                  <div className="mb-2">
                    <span className="text-gray-400 text-xs">Send to:</span>
                    <p className="font-mono text-xs bg-gray-800 p-2 rounded mt-1 break-all">{paymentState.treasuryAddress}</p>
                  </div>
                </div>

                {paymentState.error && (
                  <p className="text-red-400 text-sm">{paymentState.error}</p>
                )}

                <input
                  type="text"
                  value={txHash}
                  onChange={(e) => setTxHash(e.target.value)}
                  placeholder="Transaction hash (0x...)"
                  className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-2 text-white text-sm"
                />

                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={confirmPayment}
                    disabled={!txHash || paymentState.status === 'confirming'}
                    className="flex-1 bg-yellow-500 hover:bg-yellow-600 disabled:bg-gray-600 text-black font-medium py-2 rounded-lg"
                  >
                    {paymentState.status === 'confirming' ? 'Verifying...' : 'Verify'}
                  </button>
                  <button
                    type="button"
                    onClick={() => { reportCanceled(); setPaymentState({ status: 'idle' }); setTxHash(''); }}
                    className="px-4 bg-gray-700 hover:bg-gray-600 text-white py-2 rounded-lg"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {paymentState.status === 'confirmed' && (
              <button
                type="button"
                onClick={startPaidScan}
                className="w-full bg-arc-purple hover:bg-arc-purple/80 text-white font-medium py-3 rounded-lg"
              >
                Start Scan
              </button>
            )}
          </div>
        )}

        {/* Submit Button for Free/Trial */}
        {scanTier !== 'paid' && (
          <button
            type="button"
            onClick={handleSubmit as any}
            disabled={!canSubmit()}
            className="w-full bg-arc-purple hover:bg-arc-purple/80 disabled:bg-gray-600 text-white py-3 rounded-lg font-medium"
          >
            {loading ? 'Starting...' : scanTier === 'free' ? 'Start Free Scan' : 'Start Trial'}
          </button>
        )}
      </div>
    </div>
  );
}
