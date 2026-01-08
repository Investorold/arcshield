/**
 * GenLayer Intelligent Contract Scanner
 *
 * Scans GenLayer intelligent contracts (Python) for:
 * - Prompt injection vulnerabilities
 * - Input sanitization issues
 * - External API handling problems
 * - Non-deterministic operations without equivalence
 */

import * as fs from 'fs';
import * as path from 'path';
import type { GenLayerVulnerability, Severity, FileInfo } from '../../types/index.js';

// GenLayer-specific vulnerability patterns
interface GenLayerRule {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  description: string;
  patterns: string[];
  cwe: string;
  enabled: boolean;
  genLayerSpecific: boolean;
  fix: string;
}

interface GenLayerRulesFile {
  name: string;
  version: string;
  rules: GenLayerRule[];
}

// Load rules from JSON file
function loadGenLayerRules(): GenLayerRule[] {
  try {
    const rulesPath = path.join(__dirname, '../../rules/genlayer-rules.json');
    const content = fs.readFileSync(rulesPath, 'utf-8');
    const rulesFile: GenLayerRulesFile = JSON.parse(content);
    return rulesFile.rules.filter(r => r.enabled);
  } catch (error) {
    console.log('[GenLayer] Warning: Could not load rules file, using defaults');
    return getDefaultRules();
  }
}

// Default rules if file can't be loaded
function getDefaultRules(): GenLayerRule[] {
  return [
    {
      id: 'GL001',
      name: 'Direct User Input to LLM',
      severity: 'critical',
      category: 'prompt_injection',
      description: 'User input passed directly to LLM without sanitization',
      patterns: ['exec_prompt.*\\+.*', 'gl\\.nondet.*\\+'],
      cwe: 'CWE-77',
      enabled: true,
      genLayerSpecific: true,
      fix: 'Sanitize all user input before passing to LLM',
    },
    {
      id: 'GL002',
      name: 'Prompt Injection Patterns',
      severity: 'critical',
      category: 'prompt_injection',
      description: 'Common prompt injection patterns in string literals',
      patterns: ['ignore previous', 'disregard above', 'new instructions'],
      cwe: 'CWE-77',
      enabled: true,
      genLayerSpecific: true,
      fix: 'Filter out known injection patterns',
    },
  ];
}

/**
 * Check if a file is a GenLayer intelligent contract
 */
function isGenLayerContract(content: string): boolean {
  return (
    content.includes('from genlayer import') ||
    content.includes('import genlayer') ||
    content.includes('gl.Contract') ||
    content.includes('@gl.public')
  );
}

/**
 * Find prompt injection vulnerabilities in GenLayer contracts
 */
function findPromptInjections(
  content: string,
  filePath: string
): GenLayerVulnerability[] {
  const vulnerabilities: GenLayerVulnerability[] = [];
  const lines = content.split('\n');

  // Pattern 1: String concatenation with user input in prompts
  const promptConcatPattern = /(?:prompt|analysis_prompt|query)\s*=.*\+\s*(?:question|context|user_input|request|input)/gi;

  // Pattern 2: f-string with user variables in LLM calls
  const fstringPattern = /exec_prompt\s*\(\s*f['"]/gi;

  // Pattern 3: Direct variable interpolation in prompts
  const interpolationPattern = /exec_prompt.*\{[^}]+\}/gi;

  let vulnId = 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for prompt concatenation
    if (promptConcatPattern.test(line)) {
      vulnerabilities.push({
        id: `GL-INJ-${String(vulnId++).padStart(3, '0')}`,
        title: 'Prompt Injection: String Concatenation',
        severity: 'critical',
        threatId: '',
        description: 'User input is concatenated directly into LLM prompt without sanitization. An attacker could inject malicious instructions.',
        filePath,
        lineNumber: lineNum,
        codeSnippet: line.trim(),
        exploitability: 'High - User can inject arbitrary instructions',
        remediation: 'Sanitize user input, use parameterized prompts, implement input validation',
        aiFixPrompt: `Fix the prompt injection vulnerability at ${filePath}:${lineNum}. The code concatenates user input directly into an LLM prompt. Implement input sanitization and use a template approach instead.`,
        genLayerSpecific: true,
        genLayerRule: 'GL001',
      });
      promptConcatPattern.lastIndex = 0;
    }

    // Check for f-string prompts
    if (fstringPattern.test(line)) {
      vulnerabilities.push({
        id: `GL-INJ-${String(vulnId++).padStart(3, '0')}`,
        title: 'Prompt Injection: F-String Template',
        severity: 'high',
        threatId: '',
        description: 'F-string used in LLM call which may include unsanitized user input.',
        filePath,
        lineNumber: lineNum,
        codeSnippet: line.trim(),
        exploitability: 'Medium - Depends on what variables are interpolated',
        remediation: 'Validate and sanitize all interpolated variables before prompt execution',
        aiFixPrompt: `Review ${filePath}:${lineNum} for potential prompt injection via f-string. Ensure all interpolated variables are sanitized.`,
        genLayerSpecific: true,
        genLayerRule: 'GL001',
      });
      fstringPattern.lastIndex = 0;
    }
  }

  // Multi-line pattern detection for prompt building
  let inPromptBlock = false;
  let promptStartLine = 0;
  let promptContent = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.includes('prompt') && line.includes('=') && (line.includes('"') || line.includes("'"))) {
      inPromptBlock = true;
      promptStartLine = i + 1;
      promptContent = line;
    } else if (inPromptBlock) {
      promptContent += line;

      // Check if prompt is used with exec_prompt
      if (line.includes('exec_prompt') && promptContent.includes('+')) {
        // Check if any user-controllable variable is in the prompt
        const userVars = ['question', 'context', 'input', 'request', 'user'];
        for (const v of userVars) {
          if (promptContent.toLowerCase().includes(v)) {
            vulnerabilities.push({
              id: `GL-INJ-${String(vulnId++).padStart(3, '0')}`,
              title: 'Prompt Injection: User Input in Multi-line Prompt',
              severity: 'critical',
              threatId: '',
              description: `User-controllable variable "${v}" is included in LLM prompt without proper sanitization.`,
              filePath,
              lineNumber: promptStartLine,
              codeSnippet: promptContent.trim().substring(0, 200),
              exploitability: 'High - Attacker can manipulate prompt behavior',
              remediation: 'Implement strict input validation, use greyboxing, or structured output parsing',
              aiFixPrompt: `Critical: Fix prompt injection at ${filePath}:${promptStartLine}. User variable "${v}" flows into LLM prompt. Add sanitization function.`,
              genLayerSpecific: true,
              genLayerRule: 'GL001',
            });
            break;
          }
        }
        inPromptBlock = false;
        promptContent = '';
      }
    }
  }

  return vulnerabilities;
}

/**
 * Find missing input sanitization
 */
function findMissingSanitization(
  content: string,
  filePath: string
): GenLayerVulnerability[] {
  const vulnerabilities: GenLayerVulnerability[] = [];
  const lines = content.split('\n');
  let vulnId = 1;

  // Look for @gl.public.write functions that use request params in LLM calls
  let inPublicWrite = false;
  let functionName = '';
  let functionParams: string[] = [];
  let functionStartLine = 0;
  let functionContent = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Detect @gl.public.write decorator
    if (line.includes('@gl.public.write')) {
      inPublicWrite = true;
      continue;
    }

    // Capture function definition
    if (inPublicWrite && line.match(/^\s*def\s+(\w+)\s*\(/)) {
      const match = line.match(/def\s+(\w+)\s*\(([^)]*)\)/);
      if (match) {
        functionName = match[1];
        functionParams = match[2]
          .split(',')
          .map(p => p.split(':')[0].trim())
          .filter(p => p && p !== 'self');
        functionStartLine = lineNum;
        functionContent = '';
      }
    }

    // Collect function content
    if (functionName && lineNum > functionStartLine) {
      functionContent += line + '\n';

      // Check for LLM usage with params
      if (line.includes('exec_prompt') || line.includes('gl.llm')) {
        for (const param of functionParams) {
          if (functionContent.includes(param) && !functionContent.includes(`sanitize(${param}`)) {
            // Check if param is used in prompt context
            if (functionContent.includes(`+ ${param}`) ||
                functionContent.includes(`+${param}`) ||
                functionContent.includes(`{${param}}`)) {
              vulnerabilities.push({
                id: `GL-SAN-${String(vulnId++).padStart(3, '0')}`,
                title: 'Missing Input Sanitization',
                severity: 'high',
                threatId: '',
                description: `Parameter "${param}" in function "${functionName}" is used in LLM context without sanitization.`,
                filePath,
                lineNumber: functionStartLine,
                codeSnippet: `def ${functionName}(... ${param} ...)`,
                exploitability: 'High - External input flows to LLM unsanitized',
                remediation: `Add sanitization: sanitized_${param} = sanitize_input(${param})`,
                aiFixPrompt: `Add input sanitization for parameter "${param}" in ${filePath}:${functionStartLine}. Create a sanitize_input() function that removes injection patterns.`,
                genLayerSpecific: true,
                genLayerRule: 'GL003',
              });
            }
          }
        }
      }

      // Reset on next function or class
      if ((line.match(/^\s*def\s/) || line.match(/^\s*class\s/)) && lineNum > functionStartLine + 1) {
        inPublicWrite = false;
        functionName = '';
        functionParams = [];
      }
    }
  }

  return vulnerabilities;
}

/**
 * Find external API issues
 */
function findExternalApiIssues(
  content: string,
  filePath: string
): GenLayerVulnerability[] {
  const vulnerabilities: GenLayerVulnerability[] = [];
  const lines = content.split('\n');
  let vulnId = 1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Check for web.render without proper error handling
    if (line.includes('web.render') || line.includes('gl.fetch')) {
      // Look for try block
      let hasTry = false;
      for (let j = Math.max(0, i - 5); j < i; j++) {
        if (lines[j].includes('try:')) {
          hasTry = true;
          break;
        }
      }

      if (!hasTry) {
        vulnerabilities.push({
          id: `GL-API-${String(vulnId++).padStart(3, '0')}`,
          title: 'External API Without Error Handling',
          severity: 'medium',
          threatId: '',
          description: 'External API call without try-except block may cause contract failure.',
          filePath,
          lineNumber: lineNum,
          codeSnippet: line.trim(),
          exploitability: 'Medium - External service failure can break contract',
          remediation: 'Wrap external API calls in try-except with fallback logic',
          aiFixPrompt: `Add error handling for external API call at ${filePath}:${lineNum}. Wrap in try-except and provide fallback.`,
          genLayerSpecific: true,
          genLayerRule: 'GL004',
        });
      }
    }
  }

  return vulnerabilities;
}

/**
 * Run GenLayer scanner on files
 */
export async function runGenLayerScanner(
  files: FileInfo[]
): Promise<GenLayerVulnerability[]> {
  const vulnerabilities: GenLayerVulnerability[] = [];

  // Filter for Python files
  const pythonFiles = files.filter(f => f.path.endsWith('.py'));

  if (pythonFiles.length === 0) {
    console.log('[GenLayer] No Python files found');
    return vulnerabilities;
  }

  console.log(`[GenLayer] Scanning ${pythonFiles.length} Python file(s)...`);

  let contractCount = 0;

  for (const file of pythonFiles) {
    try {
      const content = fs.readFileSync(file.path, 'utf-8');

      // Skip non-GenLayer files
      if (!isGenLayerContract(content)) {
        continue;
      }

      contractCount++;
      const relativePath = file.path;

      // Run all checks
      const promptInjections = findPromptInjections(content, relativePath);
      const sanitizationIssues = findMissingSanitization(content, relativePath);
      const apiIssues = findExternalApiIssues(content, relativePath);

      vulnerabilities.push(...promptInjections);
      vulnerabilities.push(...sanitizationIssues);
      vulnerabilities.push(...apiIssues);

    } catch (error) {
      // Skip files that can't be read
    }
  }

  console.log(`[GenLayer] Found ${contractCount} intelligent contract(s)`);

  return vulnerabilities;
}

/**
 * Check if a project uses GenLayer
 */
export function hasGenLayerContracts(files: FileInfo[]): boolean {
  return files.some(f => {
    if (!f.path.endsWith('.py')) return false;
    try {
      const content = fs.readFileSync(f.path, 'utf-8');
      return isGenLayerContract(content);
    } catch {
      return false;
    }
  });
}

// Export scanner names for reference
export const GENLAYER_SCANNERS = {
  promptInjection: 'prompt-injection',
  inputSanitization: 'input-sanitization',
  externalApi: 'external-api',
} as const;
