/**
 * GitHub OAuth Authentication
 */

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID || 'Ov23lizuM9JUg3oCeLUK';
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '8f3c73b41451d49d99f89f210f29f3914986eb43';
const GITHUB_REDIRECT_URI = process.env.GITHUB_REDIRECT_URI || 'http://localhost:5001/api/auth/github/callback';

export interface GitHubUser {
  id: number;
  login: string;
  avatar_url: string;
  name: string;
}

export interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
  clone_url: string;
  description: string | null;
  language: string | null;
  updated_at: string;
}

/**
 * Get GitHub OAuth authorization URL
 */
export function getGitHubAuthUrl(): string {
  const params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: GITHUB_REDIRECT_URI,
    scope: 'repo read:user',
    state: Math.random().toString(36).substring(7),
  });

  return `https://github.com/login/oauth/authorize?${params}`;
}

/**
 * Exchange authorization code for access token
 */
export async function exchangeCodeForToken(code: string): Promise<string> {
  const response = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: GITHUB_REDIRECT_URI,
    }),
  });

  const data = await response.json();

  if (data.error) {
    throw new Error(data.error_description || data.error);
  }

  return data.access_token;
}

/**
 * Get authenticated user info
 */
export async function getGitHubUser(accessToken: string): Promise<GitHubUser> {
  const response = await fetch('https://api.github.com/user', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/vnd.github.v3+json',
    },
  });

  if (!response.ok) {
    throw new Error('Failed to get user info');
  }

  return response.json();
}

/**
 * Get user's repositories
 */
export async function getGitHubRepos(accessToken: string): Promise<GitHubRepo[]> {
  const repos: GitHubRepo[] = [];
  let page = 1;
  const perPage = 100;

  // Fetch all pages of repos
  while (true) {
    const response = await fetch(
      `https://api.github.com/user/repos?per_page=${perPage}&page=${page}&sort=updated`,
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Accept': 'application/vnd.github.v3+json',
        },
      }
    );

    if (!response.ok) {
      throw new Error('Failed to get repositories');
    }

    const pageRepos = await response.json();
    repos.push(...pageRepos);

    // Stop if we got fewer than perPage (last page)
    if (pageRepos.length < perPage) break;
    page++;

    // Safety limit
    if (page > 10) break;
  }

  return repos;
}

/**
 * Clone a private repo using access token
 */
export function getAuthenticatedCloneUrl(repo: GitHubRepo, accessToken: string): string {
  // Format: https://oauth2:TOKEN@github.com/owner/repo.git
  const url = new URL(repo.clone_url);
  url.username = 'oauth2';
  url.password = accessToken;
  return url.toString();
}
