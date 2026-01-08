import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { Scanner } from '@arcshield/core';
import type { ScanReport } from '@arcshield/core';
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

const app = express();
const PORT = process.env.PORT || 3501;
const FRONTEND_URL = process.env.FRONTEND_URL || '${FRONTEND_URL}';

// In-memory session storage (use Redis in production)
const sessions: Map<string, {
  accessToken: string;
  user: GitHubUser;
  repos?: GitHubRepo[];
}> = new Map();

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

// Middleware
app.use(cors());
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
// GitHub OAuth Endpoints
// ==========================================

/**
 * GET /api/auth/github - Start OAuth flow
 */
app.get('/api/auth/github', (_req, res) => {
  const authUrl = getGitHubAuthUrl();
  res.json({ url: authUrl });
});

/**
 * GET /api/auth/github/callback - OAuth callback
 */
app.get('/api/auth/github/callback', async (req, res) => {
  try {
    const { code } = req.query;

    if (!code || typeof code !== 'string') {
      return res.redirect('${FRONTEND_URL}/scan?error=no_code');
    }

    // Exchange code for token
    const accessToken = await exchangeCodeForToken(code);

    // Get user info
    const user = await getGitHubUser(accessToken);

    // Generate session ID
    const sessionId = Math.random().toString(36).substring(2) + Date.now().toString(36);

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

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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
app.listen(PORT, () => {
  console.log(`ArcShield API server running on http://localhost:${PORT}`);
  console.log(`Scans directory: ${SCANS_DIR}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
