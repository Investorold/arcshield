import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { Scanner, initializeRuleEngine, type RuleEngineConfig } from '@arcshield/core';
import type { ScanReport, Rule, RuleSet } from '@arcshield/core';
import { cloneGitHubRepo, parseGitHubUrl } from './github.js';
import { handleUpload } from './upload.js';
import {
  getGitHubAuthUrl,
  exchangeCodeForToken,
  getGitHubUser,
  getGitHubRepos,
  getAuthenticatedCloneUrl,
  type GitHubUser,
  type GitHubRepo,
} from './auth.js';
import {
  generateVerifiedBadge,
  generateScoreBadge,
  generateStatusBadge,
} from './badge.js';
import {
  verifyTransactionOnChain,
  isValidTxHash,
  getExplorerUrl,
  checkArcConnection,
} from './arc-blockchain.js';

const app = express();
const PORT = process.env.PORT || 3501;
const FRONTEND_URL = process.env.FRONTEND_URL || '${FRONTEND_URL}';

// In-memory session storage (use Redis in production)
const sessions: Map<string, {
  accessToken: string;
  user: GitHubUser;
  repos?: GitHubRepo[];
}> = new Map();

// Pending OAuth states for CSRF verification (expire after 10 minutes)
const pendingOAuthStates: Map<string, number> = new Map();

// ============================================
// WALLET TRIAL TRACKING
// ============================================

// Track which wallets have used their ONE free AI trial
// In production, use a database (PostgreSQL, Redis, etc.)
const walletTrials: Map<string, {
  usedTrial: boolean;
  trialScanId?: string;
  trialUsedAt?: string;
}> = new Map();

// File path for persisting wallet trials (simple file-based persistence)
const WALLET_TRIALS_FILE = path.join(process.env.HOME || '/root', '.arcshield', 'wallet-trials.json');

// Load wallet trials from file on startup
function loadWalletTrials(): void {
  try {
    if (fs.existsSync(WALLET_TRIALS_FILE)) {
      const data = JSON.parse(fs.readFileSync(WALLET_TRIALS_FILE, 'utf-8'));
      for (const [wallet, trial] of Object.entries(data)) {
        walletTrials.set(wallet.toLowerCase(), trial as any);
      }
      console.log(`[Wallet Trials] Loaded ${walletTrials.size} wallet records`);
    }
  } catch (error) {
    console.error('[Wallet Trials] Error loading:', error);
  }
}

// Save wallet trials to file
function saveWalletTrials(): void {
  try {
    const data: Record<string, any> = {};
    walletTrials.forEach((trial, wallet) => {
      data[wallet] = trial;
    });
    fs.writeFileSync(WALLET_TRIALS_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('[Wallet Trials] Error saving:', error);
  }
}

// Check if wallet has used their free trial
function hasUsedTrial(walletAddress: string): boolean {
  const trial = walletTrials.get(walletAddress.toLowerCase());
  return trial?.usedTrial === true;
}

// Mark wallet as having used their trial
function markTrialUsed(walletAddress: string, scanId: string): void {
  walletTrials.set(walletAddress.toLowerCase(), {
    usedTrial: true,
    trialScanId: scanId,
    trialUsedAt: new Date().toISOString(),
  });
  saveWalletTrials();
  console.log(`[Wallet Trials] Trial used by ${walletAddress.slice(0, 10)}...`);
}

// Load trials on startup
loadWalletTrials();

// ============================================
// GITHUB ACCOUNT TRIAL TRACKING
// ============================================

// Track which GitHub accounts have used their ONE free AI trial
const githubTrials: Map<string, {
  usedTrial: boolean;
  trialScanId?: string;
  trialUsedAt?: string;
  username?: string;
}> = new Map();

const GITHUB_TRIALS_FILE = path.join(process.env.HOME || '/root', '.arcshield', 'github-trials.json');

// Load GitHub trials from file
function loadGitHubTrials(): void {
  try {
    if (fs.existsSync(GITHUB_TRIALS_FILE)) {
      const data = JSON.parse(fs.readFileSync(GITHUB_TRIALS_FILE, 'utf-8'));
      for (const [id, trial] of Object.entries(data)) {
        githubTrials.set(id, trial as any);
      }
      console.log(`[GitHub Trials] Loaded ${githubTrials.size} account records`);
    }
  } catch (error) {
    console.error('[GitHub Trials] Error loading:', error);
  }
}

// Save GitHub trials to file
function saveGitHubTrials(): void {
  try {
    const data: Record<string, any> = {};
    githubTrials.forEach((trial, id) => {
      data[id] = trial;
    });
    fs.writeFileSync(GITHUB_TRIALS_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('[GitHub Trials] Error saving:', error);
  }
}

// Check if GitHub account has used their free trial
function hasGitHubUsedTrial(githubId: string): boolean {
  const trial = githubTrials.get(githubId);
  return trial?.usedTrial === true;
}

// Mark GitHub account as having used their trial
function markGitHubTrialUsed(githubId: string, username: string, scanId: string): void {
  githubTrials.set(githubId, {
    usedTrial: true,
    trialScanId: scanId,
    trialUsedAt: new Date().toISOString(),
    username,
  });
  saveGitHubTrials();
  console.log(`[GitHub Trials] Trial used by @${username} (ID: ${githubId})`);
}

// Load GitHub trials on startup
loadGitHubTrials();

// ============================================
// RATE LIMITING & SPENDING CONTROLS
// ============================================

// Configuration (can be set via environment variables)
const RATE_LIMIT_CONFIG = {
  maxScansPerHour: parseInt(process.env.MAX_SCANS_PER_HOUR || '10'),
  maxScansPerDay: parseInt(process.env.MAX_SCANS_PER_DAY || '50'),
  dailySpendingCapUSD: parseFloat(process.env.DAILY_SPENDING_CAP || '5.00'),
  warningThresholdPercent: 80, // Warn at 80% of limit
};

// Track usage per IP
const rateLimitStore: Map<string, {
  hourlyScans: { count: number; resetAt: number };
  dailyScans: { count: number; resetAt: number };
}> = new Map();

// Track daily spending
let dailySpending = {
  totalUSD: 0,
  scanCount: 0,
  resetAt: Date.now() + 24 * 60 * 60 * 1000,
};

// Get client IP
function getClientIP(req: express.Request): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
         req.socket.remoteAddress ||
         'unknown';
}

// Check rate limit for IP
function checkRateLimit(ip: string): { allowed: boolean; message?: string; remaining?: number } {
  const now = Date.now();

  // Initialize or reset rate limit data
  let limits = rateLimitStore.get(ip);
  if (!limits) {
    limits = {
      hourlyScans: { count: 0, resetAt: now + 60 * 60 * 1000 },
      dailyScans: { count: 0, resetAt: now + 24 * 60 * 60 * 1000 },
    };
    rateLimitStore.set(ip, limits);
  }

  // Reset counters if time has passed
  if (now > limits.hourlyScans.resetAt) {
    limits.hourlyScans = { count: 0, resetAt: now + 60 * 60 * 1000 };
  }
  if (now > limits.dailyScans.resetAt) {
    limits.dailyScans = { count: 0, resetAt: now + 24 * 60 * 60 * 1000 };
  }

  // Check limits
  if (limits.hourlyScans.count >= RATE_LIMIT_CONFIG.maxScansPerHour) {
    const resetIn = Math.ceil((limits.hourlyScans.resetAt - now) / 60000);
    return { allowed: false, message: `Hourly scan limit (${RATE_LIMIT_CONFIG.maxScansPerHour}) reached. Resets in ${resetIn} minutes.` };
  }
  if (limits.dailyScans.count >= RATE_LIMIT_CONFIG.maxScansPerDay) {
    const resetIn = Math.ceil((limits.dailyScans.resetAt - now) / 3600000);
    return { allowed: false, message: `Daily scan limit (${RATE_LIMIT_CONFIG.maxScansPerDay}) reached. Resets in ${resetIn} hours.` };
  }

  return {
    allowed: true,
    remaining: Math.min(
      RATE_LIMIT_CONFIG.maxScansPerHour - limits.hourlyScans.count,
      RATE_LIMIT_CONFIG.maxScansPerDay - limits.dailyScans.count
    )
  };
}

// Increment rate limit counter
function incrementRateLimit(ip: string): void {
  const limits = rateLimitStore.get(ip);
  if (limits) {
    limits.hourlyScans.count++;
    limits.dailyScans.count++;
  }
}

// Check spending limit
function checkSpendingLimit(): { allowed: boolean; message?: string; remainingUSD?: number } {
  const now = Date.now();

  // Reset daily spending
  if (now > dailySpending.resetAt) {
    console.log(`[Spending] Daily reset. Previous total: $${dailySpending.totalUSD.toFixed(4)}`);
    dailySpending = {
      totalUSD: 0,
      scanCount: 0,
      resetAt: now + 24 * 60 * 60 * 1000,
    };
  }

  const remainingUSD = RATE_LIMIT_CONFIG.dailySpendingCapUSD - dailySpending.totalUSD;

  if (remainingUSD <= 0) {
    return {
      allowed: false,
      message: `Daily spending cap ($${RATE_LIMIT_CONFIG.dailySpendingCapUSD}) reached. Resets at ${new Date(dailySpending.resetAt).toLocaleTimeString()}.`
    };
  }

  // Warn if approaching limit
  const usedPercent = (dailySpending.totalUSD / RATE_LIMIT_CONFIG.dailySpendingCapUSD) * 100;
  if (usedPercent >= RATE_LIMIT_CONFIG.warningThresholdPercent) {
    console.log(`[Spending Warning] ${usedPercent.toFixed(1)}% of daily cap used ($${dailySpending.totalUSD.toFixed(4)}/$${RATE_LIMIT_CONFIG.dailySpendingCapUSD})`);
  }

  return { allowed: true, remainingUSD };
}

// Record spending after scan
function recordSpending(costUSD: number): void {
  dailySpending.totalUSD += costUSD;
  dailySpending.scanCount++;
  console.log(`[Spending] Scan cost: $${costUSD.toFixed(4)} | Daily total: $${dailySpending.totalUSD.toFixed(4)}/$${RATE_LIMIT_CONFIG.dailySpendingCapUSD} (${dailySpending.scanCount} scans)`);
}

// Rate limit middleware for scan endpoints
function rateLimitMiddleware(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const ip = getClientIP(req);

  // Check rate limit
  const rateCheck = checkRateLimit(ip);
  if (!rateCheck.allowed) {
    res.status(429).json({ error: rateCheck.message });
    return;
  }

  // Check spending limit
  const spendCheck = checkSpendingLimit();
  if (!spendCheck.allowed) {
    res.status(429).json({ error: spendCheck.message });
    return;
  }

  // Add usage info to response headers
  res.setHeader('X-RateLimit-Remaining', rateCheck.remaining || 0);
  res.setHeader('X-SpendingLimit-Remaining', spendCheck.remainingUSD?.toFixed(2) || '0');

  next();
}

// ============================================
// END RATE LIMITING
// ============================================

// CORS Configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:3500', 'http://localhost:5173'];

if (process.env.FRONTEND_URL && !allowedOrigins.includes(process.env.FRONTEND_URL)) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`[CORS] Blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.raw({ type: 'application/zip', limit: '50mb' }));

// Scans directory
const SCANS_DIR = path.join(process.env.HOME || '/root', '.arcshield', 'scans');

// Ensure scans directory exists
if (!fs.existsSync(SCANS_DIR)) {
  fs.mkdirSync(SCANS_DIR, { recursive: true });
}

// In-memory scan status tracking
const scanStatus: Map<string, {
  status: 'pending' | 'running' | 'completed' | 'failed';
  message?: string;
  target?: string;
}> = new Map();

// Cleanup functions for temp directories
const cleanupFunctions: Map<string, () => void> = new Map();

/**
 * GET /api/scans - List all scans
 */
app.get('/api/scans', (_req, res) => {
  try {
    const files = fs.readdirSync(SCANS_DIR)
      .filter(f => f.endsWith('.json'))
      .sort((a, b) => b.localeCompare(a)); // Newest first

    const scans = files.map(file => {
      const content = fs.readFileSync(path.join(SCANS_DIR, file), 'utf-8');
      const report: ScanReport = JSON.parse(content);
      return {
        id: report.id,
        timestamp: report.timestamp,
        target: report.target,
        score: report.score,
        totalIssues: report.summary.totalIssues,
        critical: report.summary.critical,
        high: report.summary.high,
        medium: report.summary.medium,
        low: report.summary.low,
      };
    });

    res.json(scans);
  } catch (error) {
    console.error('Error listing scans:', error);
    res.status(500).json({ error: 'Failed to list scans' });
  }
});

/**
 * GET /api/scans/:id - Get scan by ID
 */
app.get('/api/scans/:id', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const report: ScanReport = JSON.parse(content);
    res.json(report);
  } catch (error) {
    console.error('Error getting scan:', error);
    res.status(500).json({ error: 'Failed to get scan' });
  }
});

/**
 * GET /api/scans/:id/status - Get scan status
 */
app.get('/api/scans/:id/status', (req, res) => {
  const { id } = req.params;
  const status = scanStatus.get(id);

  if (!status) {
    // Check if scan file exists (completed)
    const filePath = path.join(SCANS_DIR, `${id}.json`);
    if (fs.existsSync(filePath)) {
      return res.json({ id, status: 'completed' });
    }
    return res.status(404).json({ error: 'Scan not found' });
  }

  res.json({ id, ...status });
});

/**
 * POST /api/scans/github - Scan a GitHub repository
 */
app.post('/api/scans/github', rateLimitMiddleware, async (req, res) => {
  try {
    const ip = getClientIP(req);
    incrementRateLimit(ip);

    const { url, model = 'haiku', provider = 'anthropic' } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'GitHub URL is required' });
    }

    // Validate GitHub URL
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return res.status(400).json({ error: 'Invalid GitHub URL. Use format: https://github.com/owner/repo' });
    }

    // Generate scan ID
    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${parsed.owner}/${parsed.repo}`;

    // Set initial status
    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget
    });

    // Return immediately with scan ID
    res.json({ id: scanId, status: 'pending', target: displayTarget });

    // Clone and scan in background
    runGitHubScan(scanId, url, displayTarget, model, provider);
  } catch (error) {
    console.error('Error starting GitHub scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * POST /api/scans/upload - Scan uploaded ZIP file
 */
app.post('/api/scans/upload', rateLimitMiddleware, express.raw({ type: '*/*', limit: '50mb' }), async (req, res) => {
  try {
    const ip = getClientIP(req);
    incrementRateLimit(ip);

    const filename = req.headers['x-filename'] as string || 'upload.zip';
    const fileBuffer = req.body as Buffer;

    if (!fileBuffer || fileBuffer.length === 0) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const model = req.headers['x-model'] as string || 'haiku';
    const provider = req.headers['x-provider'] as string || 'anthropic';

    // Generate scan ID
    const scanId = `scan_${Date.now()}`;
    const displayTarget = `uploaded: ${filename}`;

    // Set initial status
    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Processing upload...',
      target: displayTarget
    });

    // Return immediately with scan ID
    res.json({ id: scanId, status: 'pending', target: displayTarget });

    // Process upload and scan in background
    runUploadScan(scanId, fileBuffer, filename, displayTarget, model, provider);
  } catch (error) {
    console.error('Error starting upload scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * Run GitHub scan in background
 */
async function runGitHubScan(
  scanId: string,
  url: string,
  displayTarget: string,
  model: string,
  provider: string
) {
  let cleanup: (() => void) | null = null;

  try {
    // Clone repository
    scanStatus.set(scanId, { status: 'running', message: 'Cloning repository...', target: displayTarget });
    const { path: repoPath, cleanup: repoCleanup } = await cloneGitHubRepo(url);
    cleanup = repoCleanup;
    cleanupFunctions.set(scanId, cleanup);

    // Run scan
    scanStatus.set(scanId, { status: 'running', message: 'Running security scan...', target: displayTarget });

    const scanner = new Scanner({
      target: repoPath,
      model,
      provider: provider as 'anthropic' | 'ollama',
      outputFormat: 'json',
      includeGenLayer: true,
    });

    const report = await scanner.scan();

    // Track spending
    if (report.cost) {
      recordSpending(report.cost);
    }

    // Save report with display target (not temp path)
    const filePath = path.join(SCANS_DIR, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...report,
      id: scanId,
      target: displayTarget,
    }, null, 2));

    scanStatus.set(scanId, { status: 'completed', message: 'Scan complete!', target: displayTarget });

    // Cleanup temp directory
    cleanup();
    cleanupFunctions.delete(scanId);

    // Clean up status after 5 minutes
    setTimeout(() => scanStatus.delete(scanId), 5 * 60 * 1000);
  } catch (error) {
    console.error('GitHub scan failed:', error);
    scanStatus.set(scanId, {
      status: 'failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      target: displayTarget,
    });

    // Cleanup on error
    if (cleanup) {
      cleanup();
      cleanupFunctions.delete(scanId);
    }
  }
}

/**
 * Run upload scan in background
 */
async function runUploadScan(
  scanId: string,
  fileBuffer: Buffer,
  filename: string,
  displayTarget: string,
  model: string,
  provider: string
) {
  let cleanup: (() => void) | null = null;

  try {
    // Process upload
    scanStatus.set(scanId, { status: 'running', message: 'Extracting files...', target: displayTarget });
    const { path: extractPath, cleanup: uploadCleanup } = await handleUpload(fileBuffer, filename);
    cleanup = uploadCleanup;
    cleanupFunctions.set(scanId, cleanup);

    // Run scan
    scanStatus.set(scanId, { status: 'running', message: 'Running security scan...', target: displayTarget });

    const scanner = new Scanner({
      target: extractPath,
      model,
      provider: provider as 'anthropic' | 'ollama',
      outputFormat: 'json',
      includeGenLayer: true,
    });

    const report = await scanner.scan();

    // Track spending
    if (report.cost) {
      recordSpending(report.cost);
    }

    // Save report
    const filePath = path.join(SCANS_DIR, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...report,
      id: scanId,
      target: displayTarget,
    }, null, 2));

    scanStatus.set(scanId, { status: 'completed', message: 'Scan complete!', target: displayTarget });

    // Cleanup temp directory
    cleanup();
    cleanupFunctions.delete(scanId);

    // Clean up status after 5 minutes
    setTimeout(() => scanStatus.delete(scanId), 5 * 60 * 1000);
  } catch (error) {
    console.error('Upload scan failed:', error);
    scanStatus.set(scanId, {
      status: 'failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      target: displayTarget,
    });

    // Cleanup on error
    if (cleanup) {
      cleanup();
      cleanupFunctions.delete(scanId);
    }
  }
}

/**
 * DELETE /api/scans/:id - Delete a scan
 */
app.delete('/api/scans/:id', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    fs.unlinkSync(filePath);
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting scan:', error);
    res.status(500).json({ error: 'Failed to delete scan' });
  }
});

// ==========================================
// PRICING TIERS & WALLET TRIAL ENDPOINTS
// ==========================================

/**
 * GET /api/wallet/:address/trial - Check if wallet has used their free AI trial
 */
app.get('/api/wallet/:address/trial', (req, res) => {
  const { address } = req.params;

  if (!address || address.length < 10) {
    return res.status(400).json({ error: 'Invalid wallet address' });
  }

  const trial = walletTrials.get(address.toLowerCase());

  res.json({
    walletAddress: address.toLowerCase(),
    hasUsedTrial: trial?.usedTrial === true,
    trialScanId: trial?.trialScanId || null,
    trialUsedAt: trial?.trialUsedAt || null,
  });
});

/**
 * POST /api/scans/free - Run FREE rules-only scan (no AI, no cost)
 * Unlimited for all users
 */
app.post('/api/scans/free', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'GitHub URL is required' });
    }

    // Validate GitHub URL
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return res.status(400).json({ error: 'Invalid GitHub URL' });
    }

    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${parsed.owner}/${parsed.repo}`;

    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    res.json({ id: scanId, status: 'pending', target: displayTarget, scanType: 'rules-only' });

    // Run FREE rules-only scan in background
    runFreeRulesOnlyScan(scanId, url, displayTarget);
  } catch (error) {
    console.error('Error starting free scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * GET /api/github/:sessionId/trial - Check if GitHub account has used their free trial
 */
app.get('/api/github/:sessionId/trial', (req, res) => {
  const { sessionId } = req.params;

  const session = sessions.get(sessionId);
  if (!session) {
    return res.status(401).json({ error: 'Invalid session' });
  }

  const githubId = String(session.user.id);
  const trial = githubTrials.get(githubId);

  res.json({
    githubId,
    username: session.user.login,
    hasUsedTrial: trial?.usedTrial === true,
    trialScanId: trial?.trialScanId || null,
    trialUsedAt: trial?.trialUsedAt || null,
  });
});

/**
 * POST /api/scans/repo/trial - Use ONE free AI trial for GitHub connected repo
 */
app.post('/api/scans/repo/trial', rateLimitMiddleware, async (req, res) => {
  try {
    const ip = getClientIP(req);
    const { sessionId, repoFullName, model = 'haiku' } = req.body;

    if (!sessionId || !repoFullName) {
      return res.status(400).json({ error: 'Session ID and repo name are required' });
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    const githubId = String(session.user.id);

    // Check if GitHub account has already used trial
    if (hasGitHubUsedTrial(githubId)) {
      return res.status(403).json({
        error: 'Free trial already used',
        message: `GitHub account @${session.user.login} has already used its one free AI scan trial. Please use the FREE rules-only scan or pay for AI scans.`,
      });
    }

    // Find the repo
    if (!session.repos) {
      session.repos = await getGitHubRepos(session.accessToken);
    }

    const repo = session.repos.find(r => r.full_name === repoFullName);
    if (!repo) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    incrementRateLimit(ip);

    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${repo.full_name}`;

    // Mark GitHub trial as used BEFORE starting scan
    markGitHubTrialUsed(githubId, session.user.login, scanId);

    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    res.json({
      id: scanId,
      status: 'pending',
      target: displayTarget,
      scanType: 'ai-full',
      trialUsed: true,
      githubUsername: session.user.login,
    });

    // Run full AI scan in background
    runAuthenticatedGitHubScan(scanId, repo, session.accessToken, displayTarget, model, 'anthropic');
  } catch (error) {
    console.error('Error starting GitHub trial scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * POST /api/scans/repo/free - Run FREE rules-only scan for GitHub connected repo
 */
app.post('/api/scans/repo/free', async (req, res) => {
  try {
    const { sessionId, repoFullName } = req.body;

    if (!sessionId || !repoFullName) {
      return res.status(400).json({ error: 'Session ID and repo name are required' });
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Find the repo
    if (!session.repos) {
      session.repos = await getGitHubRepos(session.accessToken);
    }

    const repo = session.repos.find(r => r.full_name === repoFullName);
    if (!repo) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${repo.full_name}`;

    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    res.json({
      id: scanId,
      status: 'pending',
      target: displayTarget,
      scanType: 'rules-only',
    });

    // Run FREE rules-only scan in background
    runAuthenticatedFreeRulesOnlyScan(scanId, repo, session.accessToken, displayTarget);
  } catch (error) {
    console.error('Error starting free repo scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * POST /api/scans/trial - Use ONE free AI trial (per wallet - for public repos)
 */
app.post('/api/scans/trial', rateLimitMiddleware, async (req, res) => {
  try {
    const ip = getClientIP(req);
    const { url, walletAddress, model = 'haiku' } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'GitHub URL is required' });
    }

    if (!walletAddress || walletAddress.length < 10) {
      return res.status(400).json({ error: 'Valid wallet address is required for trial' });
    }

    // Check if wallet has already used trial
    if (hasUsedTrial(walletAddress)) {
      return res.status(403).json({
        error: 'Free trial already used',
        message: 'This wallet has already used its one free AI scan trial. Please use the FREE rules-only scan or pay for AI scans.',
      });
    }

    // Validate GitHub URL
    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      return res.status(400).json({ error: 'Invalid GitHub URL' });
    }

    incrementRateLimit(ip);

    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${parsed.owner}/${parsed.repo}`;

    // Mark trial as used BEFORE starting scan
    markTrialUsed(walletAddress, scanId);

    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    res.json({
      id: scanId,
      status: 'pending',
      target: displayTarget,
      scanType: 'ai-full',
      trialUsed: true,
    });

    // Run full AI scan in background
    runGitHubScan(scanId, url, displayTarget, model, 'anthropic');
  } catch (error) {
    console.error('Error starting trial scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * Run FREE rules-only scan (no AI cost)
 */
async function runFreeRulesOnlyScan(
  scanId: string,
  url: string,
  displayTarget: string
) {
  let cleanup: (() => void) | null = null;

  try {
    // Clone repository
    scanStatus.set(scanId, { status: 'running', message: 'Cloning repository...', target: displayTarget });
    const { path: repoPath, cleanup: repoCleanup } = await cloneGitHubRepo(url);
    cleanup = repoCleanup;
    cleanupFunctions.set(scanId, cleanup);

    // Run rules-only scan
    scanStatus.set(scanId, { status: 'running', message: 'Running security rules scan...', target: displayTarget });

    const scanner = new Scanner({
      target: repoPath,
      model: 'haiku', // Not used for rules-only
      provider: 'anthropic', // Not used for rules-only
      outputFormat: 'json',
      includeGenLayer: true,
    });

    // Use the scanRulesOnly method (FREE - no API calls)
    const report = await scanner.scanRulesOnly();

    // Save report
    const filePath = path.join(SCANS_DIR, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...report,
      id: scanId,
      target: displayTarget,
      scanType: 'rules-only',
      cost: 0,
    }, null, 2));

    scanStatus.set(scanId, { status: 'completed', message: 'Scan complete!', target: displayTarget });

    // Cleanup
    cleanup();
    cleanupFunctions.delete(scanId);

    setTimeout(() => scanStatus.delete(scanId), 5 * 60 * 1000);
  } catch (error) {
    console.error('Free scan failed:', error);
    scanStatus.set(scanId, {
      status: 'failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      target: displayTarget,
    });

    if (cleanup) {
      cleanup();
      cleanupFunctions.delete(scanId);
    }
  }
}

// ==========================================
// USDC PAYMENT SYSTEM
// ==========================================

// Payment configuration
const PAYMENT_CONFIG = {
  treasuryAddress: process.env.TREASURY_ADDRESS || '0x68a4ca3aB8A642aa726166b25272507985B8827A', // USDC receiving address
  scanPriceUSDC: parseFloat(process.env.SCAN_PRICE_USDC || '0.15'), // $0.15 per scan
  arcRpcUrl: process.env.ARC_RPC_URL || 'https://rpc.arc.io', // Arc RPC endpoint
  paymentExpiryMinutes: 30, // Payment must be completed within 30 minutes
  // Note: No attempt limits - users can cancel and try again until expiry (industry standard)
};

// Track pending and completed payments
interface PaymentRecord {
  id: string;
  walletAddress: string;
  amount: number;
  status: 'pending' | 'confirmed' | 'expired' | 'used';
  createdAt: string;
  confirmedAt?: string;
  txHash?: string;
  scanId?: string;
  repoUrl?: string;
  // Transaction history (for analytics/debugging - does NOT limit user)
  transactionHistory?: {
    txHash?: string; // May be undefined for canceled transactions
    type: 'submitted' | 'canceled' | 'failed';
    error?: string;
    timestamp: string;
    // Details for failed on-chain transactions
    onChainStatus?: 'reverted' | 'not_found' | 'amount_mismatch' | 'wrong_recipient';
  }[];
}

const payments: Map<string, PaymentRecord> = new Map();
const PAYMENTS_FILE = path.join(process.env.HOME || '/root', '.arcshield', 'payments.json');

// Load payments from file
function loadPayments(): void {
  try {
    if (fs.existsSync(PAYMENTS_FILE)) {
      const data = JSON.parse(fs.readFileSync(PAYMENTS_FILE, 'utf-8'));
      for (const [id, payment] of Object.entries(data)) {
        payments.set(id, payment as PaymentRecord);
      }
      console.log(`[Payments] Loaded ${payments.size} payment records`);
    }
  } catch (error) {
    console.error('[Payments] Error loading:', error);
  }
}

// Save payments to file
function savePayments(): void {
  try {
    const data: Record<string, PaymentRecord> = {};
    payments.forEach((payment, id) => {
      data[id] = payment;
    });
    fs.writeFileSync(PAYMENTS_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('[Payments] Error saving:', error);
  }
}

// Generate unique payment ID
function generatePaymentId(): string {
  return `pay_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

// Load payments on startup
loadPayments();

/**
 * POST /api/payments/create - Create a new payment request
 */
app.post('/api/payments/create', (req, res) => {
  try {
    const { walletAddress, repoUrl } = req.body;

    if (!walletAddress || walletAddress.length < 10) {
      return res.status(400).json({ error: 'Valid wallet address is required' });
    }

    if (!repoUrl) {
      return res.status(400).json({ error: 'Repository URL is required' });
    }

    const paymentId = generatePaymentId();
    const payment: PaymentRecord = {
      id: paymentId,
      walletAddress: walletAddress.toLowerCase(),
      amount: PAYMENT_CONFIG.scanPriceUSDC,
      status: 'pending',
      createdAt: new Date().toISOString(),
      repoUrl,
    };

    payments.set(paymentId, payment);
    savePayments();

    res.json({
      paymentId,
      amount: PAYMENT_CONFIG.scanPriceUSDC,
      currency: 'USDC',
      treasuryAddress: PAYMENT_CONFIG.treasuryAddress,
      expiresIn: PAYMENT_CONFIG.paymentExpiryMinutes * 60, // seconds
      expiresAt: new Date(Date.now() + PAYMENT_CONFIG.paymentExpiryMinutes * 60 * 1000).toISOString(),
      instructions: `Send ${PAYMENT_CONFIG.scanPriceUSDC} USDC to ${PAYMENT_CONFIG.treasuryAddress} with payment ID: ${paymentId}`,
    });
  } catch (error) {
    console.error('Error creating payment:', error);
    res.status(500).json({ error: 'Failed to create payment' });
  }
});

/**
 * GET /api/payments/:id - Check payment status
 */
app.get('/api/payments/:id', (req, res) => {
  const { id } = req.params;
  const payment = payments.get(id);

  if (!payment) {
    return res.status(404).json({ error: 'Payment not found' });
  }

  // Check if expired
  const createdAt = new Date(payment.createdAt).getTime();
  const expiresAt = createdAt + PAYMENT_CONFIG.paymentExpiryMinutes * 60 * 1000;
  const timeRemainingMs = expiresAt - Date.now();

  if (payment.status === 'pending' && Date.now() > expiresAt) {
    payment.status = 'expired';
    savePayments();
  }

  res.json({
    ...payment,
    expiresAt: new Date(expiresAt).toISOString(),
    isExpired: payment.status === 'expired',
    timeRemaining: payment.status === 'pending' ? Math.max(0, Math.floor(timeRemainingMs / 1000)) : 0,
    canSubmitTransaction: payment.status === 'pending' && timeRemainingMs > 0,
    transactionHistory: payment.transactionHistory || [],
  });
});

/**
 * POST /api/payments/:id/confirm - Confirm payment (with tx hash)
 * Verifies the USDC transaction on Arc blockchain before confirming
 *
 * Industry standard approach (like Jumper, Uniswap, etc.):
 * - No attempt limits - user can cancel and try again until expiry
 * - Only time-based expiry limits the payment window
 * - Failed transactions are logged for analytics but don't penalize user
 */
app.post('/api/payments/:id/confirm', async (req, res) => {
  try {
    const { id } = req.params;
    const { txHash } = req.body;

    const payment = payments.get(id);

    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    if (payment.status === 'confirmed' || payment.status === 'used') {
      return res.status(400).json({ error: `Payment is already ${payment.status}` });
    }

    // Check if expired - this is the ONLY limit (industry standard)
    const createdAt = new Date(payment.createdAt).getTime();
    const expiresAt = createdAt + PAYMENT_CONFIG.paymentExpiryMinutes * 60 * 1000;
    const timeRemainingMs = expiresAt - Date.now();

    if (Date.now() > expiresAt) {
      payment.status = 'expired';
      savePayments();
      return res.status(400).json({
        error: 'Time limit reached',
        message: 'This payment window has closed. Start a new one to continue.',
        expired: true,
      });
    }

    if (!txHash) {
      return res.status(400).json({ error: 'Please provide your transaction hash' });
    }

    // Validate transaction hash format
    if (!isValidTxHash(txHash)) {
      return res.status(400).json({
        error: 'Invalid hash format',
        hint: 'Should be 66 characters starting with 0x',
      });
    }

    // Check if this transaction hash has already been used for another payment (prevent double-spend)
    for (const [existingId, existingPayment] of payments) {
      if (existingId !== id && existingPayment.txHash === txHash) {
        return res.status(400).json({
          error: 'Already used',
          message: 'This hash was used for a different payment. Use your new transaction hash.',
        });
      }
    }

    // Verify the transaction on Arc blockchain
    console.log(`[Payments] Verifying transaction ${txHash} on Arc blockchain...`);

    const verification = await verifyTransactionOnChain(
      txHash,
      payment.amount,
      PAYMENT_CONFIG.treasuryAddress,
      payment.walletAddress // Optionally verify sender matches
    );

    if (!verification.verified) {
      // Categorize the failure reason for analytics/debugging
      const errorMsg = verification.error || 'Unknown error';
      let onChainStatus: 'reverted' | 'not_found' | 'amount_mismatch' | 'wrong_recipient' | undefined;

      if (errorMsg.includes('reverted')) {
        onChainStatus = 'reverted';
      } else if (errorMsg.includes('not found') || errorMsg.includes('not yet confirmed')) {
        onChainStatus = 'not_found';
      } else if (errorMsg.includes('Amount mismatch')) {
        onChainStatus = 'amount_mismatch';
      } else if (errorMsg.includes('No USDC transfer to treasury') || errorMsg.includes('Sender mismatch')) {
        onChainStatus = 'wrong_recipient';
      }

      // Log for analytics (does NOT limit user - they can always try again)
      if (!payment.transactionHistory) {
        payment.transactionHistory = [];
      }
      payment.transactionHistory.push({
        txHash,
        type: 'failed',
        error: errorMsg,
        timestamp: new Date().toISOString(),
        onChainStatus,
      });
      savePayments();

      console.log(`[Payments] Verification failed: ${errorMsg}`);

      // User-friendly response - they can always try again until expiry
      // Create user-friendly message based on status
      let userMessage: string;
      let steps: string[];

      switch (onChainStatus) {
        case 'not_found':
          userMessage = 'Transaction not found yet. It may still be processing.';
          steps = ['Wait a few seconds', 'Click verify again'];
          break;
        case 'reverted':
          userMessage = 'Transaction failed on-chain. This usually means insufficient balance.';
          steps = ['Check your USDC balance', 'Send a new transaction', 'Verify with the new hash'];
          break;
        case 'amount_mismatch':
          userMessage = 'Wrong amount sent. Please send exactly the required amount.';
          steps = ['Send the correct amount', 'Verify with the new hash'];
          break;
        case 'wrong_recipient':
          userMessage = 'Funds sent to wrong address.';
          steps = ['Copy the correct treasury address', 'Send a new transaction', 'Verify with the new hash'];
          break;
        default:
          userMessage = errorMsg;
          steps = ['Check the explorer link below', 'Try again if needed'];
      }

      return res.status(400).json({
        error: 'Verification failed',
        message: userMessage,
        onChainStatus,
        explorerUrl: getExplorerUrl(txHash),
        details: verification.details,
        canTryAgain: true,
        timeRemaining: Math.floor(timeRemainingMs / 1000),
        nextSteps: steps,
      });
    }

    // Transaction verified! Mark as confirmed
    payment.status = 'confirmed';
    payment.confirmedAt = new Date().toISOString();
    payment.txHash = txHash;
    savePayments();

    console.log(`[Payments] Payment ${id} verified and confirmed!`);
    console.log(`[Payments] Transaction: ${txHash}`);
    console.log(`[Payments] Amount: ${verification.details?.amount} USDC`);
    console.log(`[Payments] From: ${verification.details?.from}`);
    console.log(`[Payments] Block: ${verification.details?.blockNumber}`);

    res.json({
      success: true,
      paymentId: id,
      status: 'confirmed',
      message: 'Payment confirmed! You can now start your scan.',
      verification: {
        txHash,
        amount: verification.details?.amount,
        from: verification.details?.from,
        to: verification.details?.to,
        blockNumber: verification.details?.blockNumber?.toString(),
        explorerUrl: getExplorerUrl(txHash),
      },
    });
  } catch (error) {
    console.error('Error confirming payment:', error);
    res.status(500).json({ error: 'Failed to confirm payment' });
  }
});

/**
 * POST /api/payments/:id/canceled - Report a canceled transaction (MetaMask rejection)
 *
 * Called by frontend when user clicks "Reject" in MetaMask wallet popup.
 * This is for analytics only - does NOT affect user's ability to try again.
 * User can always try again until expiry (industry standard).
 */
app.post('/api/payments/:id/canceled', (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body; // Optional: "user_rejected", "timeout", etc.

    const payment = payments.get(id);

    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    if (payment.status !== 'pending') {
      return res.status(400).json({
        error: 'Payment is not pending',
        status: payment.status,
      });
    }

    // Check if expired
    const createdAt = new Date(payment.createdAt).getTime();
    const expiresAt = createdAt + PAYMENT_CONFIG.paymentExpiryMinutes * 60 * 1000;
    const timeRemainingMs = expiresAt - Date.now();

    if (Date.now() > expiresAt) {
      payment.status = 'expired';
      savePayments();
      return res.status(400).json({
        error: 'Time limit reached',
        message: 'Start a new payment to continue.',
      });
    }

    // Log canceled transaction for analytics (does NOT limit user)
    if (!payment.transactionHistory) {
      payment.transactionHistory = [];
    }
    payment.transactionHistory.push({
      type: 'canceled',
      error: reason || 'Rejected in wallet',
      timestamp: new Date().toISOString(),
    });
    savePayments();

    console.log(`[Payments] Transaction canceled for payment ${id}: ${reason || 'user_rejected'}`);

    // User can always try again - this is just logging for analytics
    res.json({
      success: true,
      message: 'No problem! Try again when ready.',
      paymentId: id,
      status: 'pending',
      timeRemaining: Math.floor(timeRemainingMs / 1000),
      canTryAgain: true,
    });
  } catch (error) {
    console.error('Error logging canceled transaction:', error);
    res.status(500).json({ error: 'Failed to log canceled transaction' });
  }
});

/**
 * POST /api/scans/paid - Run a paid AI scan (requires confirmed payment)
 */
app.post('/api/scans/paid', rateLimitMiddleware, async (req, res) => {
  try {
    const ip = getClientIP(req);
    const { paymentId, model = 'haiku' } = req.body;

    if (!paymentId) {
      return res.status(400).json({ error: 'Payment ID is required' });
    }

    const payment = payments.get(paymentId);

    if (!payment) {
      return res.status(404).json({ error: 'Payment not found' });
    }

    if (payment.status !== 'confirmed') {
      // Clear, friendly messages for each status
      let errorMessage: string;

      switch (payment.status) {
        case 'pending':
          errorMessage = 'Complete your payment first, then come back to start the scan.';
          break;
        case 'used':
          errorMessage = 'Already used. Start a new payment for another scan.';
          break;
        case 'expired':
          errorMessage = 'Time limit reached. Start a new payment to continue.';
          break;
        default:
          errorMessage = 'Something went wrong. Please start a new payment.';
      }

      return res.status(400).json({
        error: 'Not ready yet',
        status: payment.status,
        message: errorMessage,
        // For pending payments, user can try again
        ...(payment.status === 'pending' && {
          canTryAgain: true,
          transactionHistory: payment.transactionHistory || [],
        }),
      });
    }

    if (!payment.repoUrl) {
      return res.status(400).json({ error: 'No repository linked. Please start over.' });
    }

    // Validate GitHub URL
    const parsed = parseGitHubUrl(payment.repoUrl);
    if (!parsed) {
      return res.status(400).json({ error: 'Invalid GitHub URL in payment' });
    }

    incrementRateLimit(ip);

    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${parsed.owner}/${parsed.repo}`;

    // Mark payment as used
    payment.status = 'used';
    payment.scanId = scanId;
    savePayments();

    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    res.json({
      id: scanId,
      status: 'pending',
      target: displayTarget,
      scanType: 'ai-full',
      paymentId,
      paid: true,
    });

    // Run full AI scan
    runGitHubScan(scanId, payment.repoUrl, displayTarget, model, 'anthropic');
  } catch (error) {
    console.error('Error starting paid scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * GET /api/pricing - Get current pricing tiers
 */
app.get('/api/pricing', (_req, res) => {
  res.json({
    tiers: [
      {
        id: 'free',
        name: 'Free',
        price: 0,
        priceDisplay: 'FREE',
        description: 'Rule-based security scan',
        features: [
          '91 built-in security rules',
          '20 Arc-specific rules',
          'Pattern-based vulnerability detection',
          'Unlimited scans',
          'Instant results',
        ],
        limitations: [
          'No AI-powered analysis',
          'No STRIDE threat modeling',
          'No deep code review',
        ],
      },
      {
        id: 'trial',
        name: 'Free Trial',
        price: 0,
        priceDisplay: 'FREE (1x)',
        description: 'One free AI-powered scan per wallet',
        features: [
          'Everything in Free tier',
          'Full AI-powered analysis',
          'STRIDE threat modeling',
          'Deep code review',
          'Detailed remediation steps',
        ],
        limitations: [
          'One scan per wallet address',
        ],
      },
      {
        id: 'paid',
        name: 'Pay Per Scan',
        price: PAYMENT_CONFIG.scanPriceUSDC,
        priceDisplay: `$${PAYMENT_CONFIG.scanPriceUSDC.toFixed(2)} USDC`,
        description: 'Full AI-powered security audit',
        features: [
          'Everything in Trial tier',
          'Unlimited AI scans',
          'Priority processing',
          'Advanced reporting',
        ],
        limitations: [],
        treasuryAddress: PAYMENT_CONFIG.treasuryAddress,
      },
    ],
    payment: {
      currency: 'USDC',
      network: 'Arc',
      treasuryAddress: PAYMENT_CONFIG.treasuryAddress,
      scanPrice: PAYMENT_CONFIG.scanPriceUSDC,
    },
  });
});

// ==========================================
// GitHub OAuth Endpoints
// ==========================================

/**
 * GET /api/auth/github - Start OAuth flow
 */
app.get('/api/auth/github', (_req, res) => {
  // Clean up expired states (older than 10 minutes)
  const now = Date.now();
  for (const [state, timestamp] of pendingOAuthStates.entries()) {
    if (now - timestamp > 10 * 60 * 1000) {
      pendingOAuthStates.delete(state);
    }
  }

  const { url, state } = getGitHubAuthUrl();

  // Store state for CSRF verification
  pendingOAuthStates.set(state, now);

  res.json({ url });
});

/**
 * GET /api/auth/github/callback - OAuth callback
 */
app.get('/api/auth/github/callback', async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || typeof code !== 'string') {
      return res.redirect(`${FRONTEND_URL}/scan?error=no_code`);
    }

    // Verify CSRF state
    if (!state || typeof state !== 'string' || !pendingOAuthStates.has(state)) {
      console.warn('[OAuth] Invalid or missing state parameter - possible CSRF attack');
      return res.redirect(`${FRONTEND_URL}/scan?error=invalid_state`);
    }

    // Remove used state (one-time use)
    pendingOAuthStates.delete(state);

    // Exchange code for token
    const accessToken = await exchangeCodeForToken(code);

    // Get user info
    const user = await getGitHubUser(accessToken);

    // Generate cryptographically secure session ID
    const sessionId = crypto.randomUUID();

    // Store session
    sessions.set(sessionId, { accessToken, user });

    // Redirect to frontend with session ID
    res.redirect(`${FRONTEND_URL}/scan?session=${sessionId}`);
  } catch (error) {
    console.error('OAuth callback error:', error);
    res.redirect(`${FRONTEND_URL}/scan?error=${encodeURIComponent(error instanceof Error ? error.message : 'auth_failed')}`);
  }
});

/**
 * GET /api/auth/session/:id - Get session info
 */
app.get('/api/auth/session/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const session = sessions.get(id);

    if (!session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Return user info (not token)
    res.json({
      user: session.user,
      hasRepos: !!session.repos,
    });
  } catch (error) {
    console.error('Session error:', error);
    res.status(500).json({ error: 'Failed to get session' });
  }
});

/**
 * GET /api/auth/repos/:sessionId - Get user's repositories
 */
app.get('/api/auth/repos/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);

    if (!session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Fetch repos if not cached
    if (!session.repos) {
      session.repos = await getGitHubRepos(session.accessToken);
    }

    // Return repos (without sensitive data)
    res.json(session.repos.map(repo => ({
      id: repo.id,
      name: repo.name,
      full_name: repo.full_name,
      private: repo.private,
      html_url: repo.html_url,
      description: repo.description,
      language: repo.language,
      updated_at: repo.updated_at,
    })));
  } catch (error) {
    console.error('Repos error:', error);
    res.status(500).json({ error: 'Failed to get repositories' });
  }
});

/**
 * POST /api/auth/logout/:sessionId - Logout
 */
app.post('/api/auth/logout/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  sessions.delete(sessionId);
  res.json({ success: true });
});

/**
 * POST /api/scans/repo - Scan a repo from connected GitHub account
 */
app.post('/api/scans/repo', rateLimitMiddleware, async (req, res) => {
  try {
    const ip = getClientIP(req);
    incrementRateLimit(ip);

    const { sessionId, repoFullName, model = 'haiku', provider = 'anthropic' } = req.body;

    if (!sessionId || !repoFullName) {
      return res.status(400).json({ error: 'Session ID and repo name are required' });
    }

    const session = sessions.get(sessionId);
    if (!session) {
      return res.status(401).json({ error: 'Invalid session' });
    }

    // Find the repo
    if (!session.repos) {
      session.repos = await getGitHubRepos(session.accessToken);
    }

    const repo = session.repos.find(r => r.full_name === repoFullName);
    if (!repo) {
      return res.status(404).json({ error: 'Repository not found' });
    }

    // Generate scan ID
    const scanId = `scan_${Date.now()}`;
    const displayTarget = `github.com/${repo.full_name}`;

    // Set initial status
    scanStatus.set(scanId, {
      status: 'pending',
      message: 'Cloning repository...',
      target: displayTarget,
    });

    // Return immediately
    res.json({ id: scanId, status: 'pending', target: displayTarget });

    // Clone and scan in background
    runAuthenticatedGitHubScan(scanId, repo, session.accessToken, displayTarget, model, provider);
  } catch (error) {
    console.error('Error starting repo scan:', error);
    res.status(500).json({ error: 'Failed to start scan' });
  }
});

/**
 * Clone and scan with authentication (for private repos)
 */
async function runAuthenticatedGitHubScan(
  scanId: string,
  repo: GitHubRepo,
  accessToken: string,
  displayTarget: string,
  model: string,
  provider: string
) {
  let tempDir: string | null = null;

  try {
    // Clone repository
    scanStatus.set(scanId, { status: 'running', message: 'Cloning repository...', target: displayTarget });

    // Create temp directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arcshield-'));
    const repoPath = path.join(tempDir, repo.name);

    // Clone with auth
    const cloneUrl = getAuthenticatedCloneUrl(repo, accessToken);
    console.log(`[GitHub] Cloning ${repo.full_name}...`);
    execSync(`git clone --depth 1 ${cloneUrl} ${repoPath}`, {
      stdio: 'pipe',
      timeout: 120000,
    });

    // Run scan
    scanStatus.set(scanId, { status: 'running', message: 'Running security scan...', target: displayTarget });

    const scanner = new Scanner({
      target: repoPath,
      model,
      provider: provider as 'anthropic' | 'ollama',
      outputFormat: 'json',
      includeGenLayer: true,
    });

    const report = await scanner.scan();

    // Track spending
    if (report.cost) {
      recordSpending(report.cost);
    }

    // Save report
    const filePath = path.join(SCANS_DIR, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...report,
      id: scanId,
      target: displayTarget,
    }, null, 2));

    scanStatus.set(scanId, { status: 'completed', message: 'Scan complete!', target: displayTarget });

    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });

    setTimeout(() => scanStatus.delete(scanId), 5 * 60 * 1000);
  } catch (error) {
    console.error('Authenticated scan failed:', error);
    scanStatus.set(scanId, {
      status: 'failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      target: displayTarget,
    });

    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

/**
 * Run FREE rules-only scan for authenticated GitHub repos (no AI cost)
 */
async function runAuthenticatedFreeRulesOnlyScan(
  scanId: string,
  repo: GitHubRepo,
  accessToken: string,
  displayTarget: string
) {
  let tempDir: string | null = null;

  try {
    // Clone repository
    scanStatus.set(scanId, { status: 'running', message: 'Cloning repository...', target: displayTarget });

    // Create temp directory
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arcshield-'));
    const repoPath = path.join(tempDir, repo.name);

    // Clone with auth
    const cloneUrl = getAuthenticatedCloneUrl(repo, accessToken);
    console.log(`[GitHub] Cloning ${repo.full_name} (FREE scan)...`);
    execSync(`git clone --depth 1 ${cloneUrl} ${repoPath}`, {
      stdio: 'pipe',
      timeout: 120000,
    });

    // Run rules-only scan
    scanStatus.set(scanId, { status: 'running', message: 'Running security rules scan...', target: displayTarget });

    const scanner = new Scanner({
      target: repoPath,
      model: 'haiku', // Not used for rules-only
      provider: 'anthropic', // Not used for rules-only
      outputFormat: 'json',
      includeGenLayer: true,
    });

    // Use the scanRulesOnly method (FREE - no API calls)
    const report = await scanner.scanRulesOnly();

    // Save report
    const filePath = path.join(SCANS_DIR, `${scanId}.json`);
    fs.writeFileSync(filePath, JSON.stringify({
      ...report,
      id: scanId,
      target: displayTarget,
      scanType: 'rules-only',
      cost: 0,
    }, null, 2));

    scanStatus.set(scanId, { status: 'completed', message: 'Scan complete!', target: displayTarget });

    // Cleanup
    fs.rmSync(tempDir, { recursive: true, force: true });

    setTimeout(() => scanStatus.delete(scanId), 5 * 60 * 1000);
  } catch (error) {
    console.error('Authenticated free scan failed:', error);
    scanStatus.set(scanId, {
      status: 'failed',
      message: error instanceof Error ? error.message : 'Unknown error',
      target: displayTarget,
    });

    if (tempDir) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  }
}

// Usage stats endpoint (for monitoring)
app.get('/api/usage', (_req, res) => {
  const now = Date.now();

  // Reset if needed
  if (now > dailySpending.resetAt) {
    dailySpending = {
      totalUSD: 0,
      scanCount: 0,
      resetAt: now + 24 * 60 * 60 * 1000,
    };
  }

  res.json({
    spending: {
      todayUSD: dailySpending.totalUSD,
      dailyCapUSD: RATE_LIMIT_CONFIG.dailySpendingCapUSD,
      remainingUSD: Math.max(0, RATE_LIMIT_CONFIG.dailySpendingCapUSD - dailySpending.totalUSD),
      scanCount: dailySpending.scanCount,
      resetsAt: new Date(dailySpending.resetAt).toISOString(),
    },
    limits: {
      maxScansPerHour: RATE_LIMIT_CONFIG.maxScansPerHour,
      maxScansPerDay: RATE_LIMIT_CONFIG.maxScansPerDay,
      dailySpendingCapUSD: RATE_LIMIT_CONFIG.dailySpendingCapUSD,
    },
  });
});

// ==========================================
// Badge Endpoints
// ==========================================

/**
 * GET /api/badge/:id/verified.svg - Get verified status badge
 */
app.get('/api/badge/:id/verified.svg', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      // Return "Unknown" badge if scan not found
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Cache-Control', 'no-cache');
      return res.send(generateVerifiedBadge(false));
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const report: ScanReport = JSON.parse(content);

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=300'); // Cache for 5 minutes
    res.send(generateVerifiedBadge(report.badge.eligible));
  } catch (error) {
    console.error('Error generating badge:', error);
    res.status(500).send('Error generating badge');
  }
});

/**
 * GET /api/badge/:id/score.svg - Get score badge
 */
app.get('/api/badge/:id/score.svg', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Cache-Control', 'no-cache');
      return res.send(generateScoreBadge(0));
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const report: ScanReport = JSON.parse(content);

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(generateScoreBadge(report.score));
  } catch (error) {
    console.error('Error generating badge:', error);
    res.status(500).send('Error generating badge');
  }
});

/**
 * GET /api/badge/:id/status.svg - Get combined status badge
 */
app.get('/api/badge/:id/status.svg', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Cache-Control', 'no-cache');
      return res.send(generateStatusBadge(0, false));
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const report: ScanReport = JSON.parse(content);

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(generateStatusBadge(report.score, report.badge.eligible));
  } catch (error) {
    console.error('Error generating badge:', error);
    res.status(500).send('Error generating badge');
  }
});

/**
 * GET /api/badge/:id/embed - Get embed code for badges
 */
app.get('/api/badge/:id/embed', (req, res) => {
  try {
    const { id } = req.params;
    const filePath = path.join(SCANS_DIR, `${id}.json`);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    const report: ScanReport = JSON.parse(content);

    // Base URL (use environment variable in production)
    const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;

    res.json({
      scanId: id,
      score: report.score,
      eligible: report.badge.eligible,
      badges: {
        verified: {
          url: `${baseUrl}/api/badge/${id}/verified.svg`,
          markdown: `![ArcShield Verified](${baseUrl}/api/badge/${id}/verified.svg)`,
          html: `<img src="${baseUrl}/api/badge/${id}/verified.svg" alt="ArcShield Verified" />`,
        },
        score: {
          url: `${baseUrl}/api/badge/${id}/score.svg`,
          markdown: `![ArcShield Score](${baseUrl}/api/badge/${id}/score.svg)`,
          html: `<img src="${baseUrl}/api/badge/${id}/score.svg" alt="ArcShield Score" />`,
        },
        status: {
          url: `${baseUrl}/api/badge/${id}/status.svg`,
          markdown: `![ArcShield Status](${baseUrl}/api/badge/${id}/status.svg)`,
          html: `<img src="${baseUrl}/api/badge/${id}/status.svg" alt="ArcShield Status" />`,
        },
      },
    });
  } catch (error) {
    console.error('Error getting embed code:', error);
    res.status(500).json({ error: 'Failed to get embed code' });
  }
});

// ==========================================
// Rules API - Rule Management
// ==========================================

// Singleton rule engine
let ruleEngine: Awaited<ReturnType<typeof initializeRuleEngine>> | null = null;

async function getRuleEngine() {
  if (!ruleEngine) {
    ruleEngine = await initializeRuleEngine();
  }
  return ruleEngine;
}

// GET /api/rules - Get all loaded rules
app.get('/api/rules', async (_req, res) => {
  try {
    const engine = await getRuleEngine();
    const rules = engine.getRules();
    res.json({
      success: true,
      count: rules.length,
      rules,
    });
  } catch (error) {
    console.error('Error getting rules:', error);
    res.status(500).json({ error: 'Failed to load rules' });
  }
});

// GET /api/rules/stats - Get rule statistics
app.get('/api/rules/stats', async (_req, res) => {
  try {
    const engine = await getRuleEngine();
    const stats = engine.getStats();
    res.json({
      success: true,
      stats,
    });
  } catch (error) {
    console.error('Error getting rule stats:', error);
    res.status(500).json({ error: 'Failed to get rule stats' });
  }
});

// GET /api/rulesets - Get all rule sets
app.get('/api/rulesets', async (_req, res) => {
  try {
    const engine = await getRuleEngine();
    const ruleSets = engine.getRuleSets();
    res.json({
      success: true,
      count: ruleSets.length,
      ruleSets: ruleSets.map(rs => ({
        name: rs.name,
        version: rs.version,
        description: rs.description,
        author: rs.author,
        ruleCount: rs.rules.length,
      })),
    });
  } catch (error) {
    console.error('Error getting rule sets:', error);
    res.status(500).json({ error: 'Failed to load rule sets' });
  }
});

// GET /api/rules/:id - Get a specific rule
app.get('/api/rules/:id', async (req, res) => {
  try {
    const engine = await getRuleEngine();
    const rule = engine.getRule(req.params.id);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    res.json({
      success: true,
      rule,
    });
  } catch (error) {
    console.error('Error getting rule:', error);
    res.status(500).json({ error: 'Failed to get rule' });
  }
});

// GET /api/rules/category/:category - Get rules by category
app.get('/api/rules/category/:category', async (req, res) => {
  try {
    const engine = await getRuleEngine();
    const rules = engine.getRulesByCategory(req.params.category as any);
    res.json({
      success: true,
      category: req.params.category,
      count: rules.length,
      rules,
    });
  } catch (error) {
    console.error('Error getting rules by category:', error);
    res.status(500).json({ error: 'Failed to get rules' });
  }
});

// GET /api/rules/severity/:severity - Get rules by severity
app.get('/api/rules/severity/:severity', async (req, res) => {
  try {
    const engine = await getRuleEngine();
    const rules = engine.getRulesBySeverity(req.params.severity as any);
    res.json({
      success: true,
      severity: req.params.severity,
      count: rules.length,
      rules,
    });
  } catch (error) {
    console.error('Error getting rules by severity:', error);
    res.status(500).json({ error: 'Failed to get rules' });
  }
});

// POST /api/rules/:id/enable - Enable a rule
app.post('/api/rules/:id/enable', async (req, res) => {
  try {
    const engine = await getRuleEngine();
    const success = engine.enableRule(req.params.id);
    if (!success) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    res.json({
      success: true,
      message: `Rule ${req.params.id} enabled`,
    });
  } catch (error) {
    console.error('Error enabling rule:', error);
    res.status(500).json({ error: 'Failed to enable rule' });
  }
});

// POST /api/rules/:id/disable - Disable a rule
app.post('/api/rules/:id/disable', async (req, res) => {
  try {
    const engine = await getRuleEngine();
    const success = engine.disableRule(req.params.id);
    if (!success) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    res.json({
      success: true,
      message: `Rule ${req.params.id} disabled`,
    });
  } catch (error) {
    console.error('Error disabling rule:', error);
    res.status(500).json({ error: 'Failed to disable rule' });
  }
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Arc blockchain connection check
app.get('/api/arc/status', async (_req, res) => {
  try {
    const connected = await checkArcConnection();
    res.json({
      connected,
      network: 'Arc Testnet',
      rpcUrl: process.env.ARC_RPC_URL || 'https://rpc.testnet.arc.network',
      treasuryAddress: PAYMENT_CONFIG.treasuryAddress,
      scanPriceUSDC: PAYMENT_CONFIG.scanPriceUSDC,
    });
  } catch (error) {
    res.status(503).json({
      connected: false,
      error: 'Failed to connect to Arc blockchain',
    });
  }
});

// ==========================================
// Production Static File Serving
// ==========================================

// In production, serve the built React app
if (process.env.NODE_ENV === 'production') {
  const distPath = path.join(import.meta.dirname, '../../dist');

  // Serve static files
  app.use(express.static(distPath));

  // SPA fallback - serve index.html for all non-API routes
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api')) {
      res.sendFile(path.join(distPath, 'index.html'));
    }
  });

  console.log(`Serving static files from: ${distPath}`);
}

// Start server
app.listen(PORT, async () => {
  console.log(`ArcShield API server running on http://localhost:${PORT}`);
  console.log(`Scans directory: ${SCANS_DIR}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);

  // Check Arc blockchain connection
  console.log('\n[Arc] Checking blockchain connection...');
  const arcConnected = await checkArcConnection();
  if (arcConnected) {
    console.log('[Arc] ✓ Connected to Arc blockchain');
    console.log(`[Arc] Treasury: ${PAYMENT_CONFIG.treasuryAddress}`);
    console.log(`[Arc] Scan price: ${PAYMENT_CONFIG.scanPriceUSDC} USDC`);
  } else {
    console.warn('[Arc] ⚠ Could not connect to Arc blockchain');
    console.warn('[Arc] Payment verification will fail until connection is restored');
  }
});
