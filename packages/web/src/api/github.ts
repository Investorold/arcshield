import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Parse GitHub URL to extract owner and repo
 */
export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  // Support various GitHub URL formats:
  // https://github.com/owner/repo
  // https://github.com/owner/repo.git
  // git@github.com:owner/repo.git
  // github.com/owner/repo

  const patterns = [
    /github\.com[\/:]([^\/]+)\/([^\/\.]+)/,
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace(/\.git$/, ''),
      };
    }
  }

  return null;
}

/**
 * Clone a GitHub repository to a temporary directory
 */
export async function cloneGitHubRepo(url: string): Promise<{ path: string; cleanup: () => void }> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) {
    throw new Error('Invalid GitHub URL. Please use format: https://github.com/owner/repo');
  }

  // Create temp directory
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'arcshield-'));
  const repoPath = path.join(tempDir, parsed.repo);

  try {
    // Clone the repository (shallow clone for speed)
    console.log(`[GitHub] Cloning ${parsed.owner}/${parsed.repo}...`);

    const gitUrl = `https://github.com/${parsed.owner}/${parsed.repo}.git`;
    execSync(`git clone --depth 1 ${gitUrl} ${repoPath}`, {
      stdio: 'pipe',
      timeout: 60000, // 60 second timeout
    });

    console.log(`[GitHub] Cloned to ${repoPath}`);

    return {
      path: repoPath,
      cleanup: () => {
        try {
          fs.rmSync(tempDir, { recursive: true, force: true });
          console.log(`[GitHub] Cleaned up ${tempDir}`);
        } catch (e) {
          console.error(`[GitHub] Failed to cleanup ${tempDir}:`, e);
        }
      },
    };
  } catch (error) {
    // Cleanup on error
    fs.rmSync(tempDir, { recursive: true, force: true });

    if (error instanceof Error && error.message.includes('not found')) {
      throw new Error(`Repository not found: ${parsed.owner}/${parsed.repo}`);
    }
    throw new Error(`Failed to clone repository: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Check if a GitHub repo exists and is accessible
 */
export async function checkGitHubRepo(url: string): Promise<boolean> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) return false;

  try {
    const response = await fetch(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`);
    return response.ok;
  } catch {
    return false;
  }
}
