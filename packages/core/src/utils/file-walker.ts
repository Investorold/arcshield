/**
 * File Walker Utility
 * Recursively walks through directories and collects files for scanning
 */

import * as fs from 'fs';
import * as path from 'path';
import ignore from 'ignore';
import { glob } from 'glob';
import { EXCLUDED_PATTERNS, LANGUAGE_EXTENSIONS } from '../constants.js';
import type { FileContext } from '../types/index.js';

export interface FileWalkerOptions {
  rootDir: string;
  includePatterns?: string[];
  excludePatterns?: string[];
  respectGitignore?: boolean;
  maxFileSize?: number; // in bytes
  maxFiles?: number;
}

const DEFAULT_OPTIONS: Partial<FileWalkerOptions> = {
  respectGitignore: true,
  maxFileSize: 1024 * 1024, // 1MB
  maxFiles: 1000,
};

/**
 * Get the programming language based on file extension
 */
export function getLanguageFromExtension(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();

  for (const [language, extensions] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (extensions.includes(ext)) {
      return language;
    }
  }

  return 'unknown';
}

/**
 * Load .gitignore patterns from a directory
 */
function loadGitignore(dir: string): string[] {
  const gitignorePath = path.join(dir, '.gitignore');

  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    return content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
  }

  return [];
}

/**
 * Walk through a directory and collect files for scanning
 */
export async function walkFiles(options: FileWalkerOptions): Promise<FileContext[]> {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const { rootDir, respectGitignore, maxFileSize, maxFiles } = opts;

  // Build ignore patterns
  const ignorePatterns = [...EXCLUDED_PATTERNS, ...(opts.excludePatterns || [])];

  if (respectGitignore) {
    ignorePatterns.push(...loadGitignore(rootDir));
  }

  const ig = ignore().add(ignorePatterns);

  // Find all files
  const allExtensions = Object.values(LANGUAGE_EXTENSIONS).flat();
  const globPattern = `**/*{${allExtensions.join(',')}}`;

  const files = await glob(globPattern, {
    cwd: rootDir,
    nodir: true,
    absolute: false,
  });

  // Filter and collect files
  const fileContexts: FileContext[] = [];

  for (const file of files) {
    // Check max files limit
    if (fileContexts.length >= maxFiles!) {
      break;
    }

    // Check if ignored
    if (ig.ignores(file)) {
      continue;
    }

    const absolutePath = path.join(rootDir, file);

    // Check file size
    const stats = fs.statSync(absolutePath);
    if (stats.size > maxFileSize!) {
      continue;
    }

    // Read file content
    try {
      const content = fs.readFileSync(absolutePath, 'utf-8');
      const lines = content.split('\n').length;
      const language = getLanguageFromExtension(file);

      fileContexts.push({
        path: file,
        content,
        language,
        lines,
      });
    } catch (error) {
      // Skip files that can't be read
      console.warn(`Warning: Could not read file ${file}`);
    }
  }

  return fileContexts;
}

/**
 * Get a summary of files by language
 */
export function getFileSummary(files: FileContext[]): Record<string, number> {
  const summary: Record<string, number> = {};

  for (const file of files) {
    summary[file.language] = (summary[file.language] || 0) + 1;
  }

  return summary;
}

/**
 * Get total lines of code
 */
export function getTotalLines(files: FileContext[]): number {
  return files.reduce((total, file) => total + file.lines, 0);
}
