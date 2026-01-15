import { useMemo } from 'react';
import { Highlight, themes } from 'prism-react-renderer';
import type { Vulnerability, ArcVulnerability, Severity } from '../../types';

type VulnItem = Vulnerability | ArcVulnerability;

interface CodeViewerProps {
  code: string;
  language: string;
  vulnerabilities: VulnItem[];
  selectedVulnId: string | null;
  onSelectVuln: (vuln: VulnItem) => void;
}

const SEVERITY_BG: Record<Severity, string> = {
  critical: 'bg-red-500/20 border-l-red-500',
  high: 'bg-orange-500/20 border-l-orange-500',
  medium: 'bg-yellow-500/20 border-l-yellow-500',
  low: 'bg-green-500/20 border-l-green-500',
  info: 'bg-gray-500/20 border-l-gray-500',
};

const SEVERITY_ICON: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🟢',
  info: '⚪',
};

// Detect language from file extension
export function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() || '';
  const languageMap: Record<string, string> = {
    js: 'javascript',
    jsx: 'jsx',
    ts: 'typescript',
    tsx: 'tsx',
    py: 'python',
    rb: 'ruby',
    go: 'go',
    rs: 'rust',
    sol: 'solidity',
    java: 'java',
    kt: 'kotlin',
    swift: 'swift',
    c: 'c',
    cpp: 'cpp',
    h: 'c',
    hpp: 'cpp',
    cs: 'csharp',
    php: 'php',
    sql: 'sql',
    sh: 'bash',
    bash: 'bash',
    zsh: 'bash',
    yml: 'yaml',
    yaml: 'yaml',
    json: 'json',
    xml: 'markup',
    html: 'markup',
    css: 'css',
    scss: 'scss',
    md: 'markdown',
  };
  return languageMap[ext] || 'typescript';
}

export default function CodeViewer({
  code,
  language,
  vulnerabilities,
  selectedVulnId,
  onSelectVuln,
}: CodeViewerProps) {
  // Map line numbers to vulnerabilities
  const vulnsByLine = useMemo(() => {
    const map = new Map<number, VulnItem[]>();
    vulnerabilities.forEach((vuln) => {
      const line = vuln.lineNumber;
      const existing = map.get(line) || [];
      existing.push(vuln);
      map.set(line, existing);
    });
    return map;
  }, [vulnerabilities]);

  // Get highest severity for a line
  const getLineSeverity = (lineNum: number): Severity | null => {
    const vulns = vulnsByLine.get(lineNum);
    if (!vulns || vulns.length === 0) return null;

    const priorities: Record<Severity, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    };

    return vulns.reduce((max, v) => {
      if (!max || priorities[v.severity] > priorities[max]) {
        return v.severity;
      }
      return max;
    }, null as Severity | null);
  };

  // Check if line has selected vulnerability
  const isLineSelected = (lineNum: number): boolean => {
    if (!selectedVulnId) return false;
    const vulns = vulnsByLine.get(lineNum);
    return vulns?.some((v) => v.id === selectedVulnId) || false;
  };

  if (!code) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        Select a file to view code
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto bg-gray-900 font-mono text-sm">
      <Highlight theme={themes.nightOwl} code={code} language={language}>
        {({ className, style, tokens, getLineProps, getTokenProps }) => (
          <pre className={`${className} min-h-full`} style={{ ...style, background: 'transparent', margin: 0, padding: '1rem 0' }}>
            {tokens.map((line, lineIndex) => {
              const lineNum = lineIndex + 1;
              const severity = getLineSeverity(lineNum);
              const hasVuln = severity !== null;
              const isSelected = isLineSelected(lineNum);
              const lineVulns = vulnsByLine.get(lineNum) || [];

              return (
                <div
                  key={lineIndex}
                  {...getLineProps({ line })}
                  className={`flex hover:bg-gray-800/50 ${
                    hasVuln ? `${SEVERITY_BG[severity]} border-l-2` : ''
                  } ${isSelected ? 'ring-1 ring-arc-purple' : ''}`}
                  onClick={() => {
                    if (lineVulns.length > 0) {
                      onSelectVuln(lineVulns[0]);
                    }
                  }}
                  style={{ cursor: hasVuln ? 'pointer' : 'default' }}
                >
                  {/* Line number gutter */}
                  <span className="select-none text-gray-600 text-right pr-4 pl-4 min-w-[4rem] border-r border-gray-800">
                    {lineNum}
                  </span>

                  {/* Vulnerability indicator */}
                  <span className="select-none w-6 text-center">
                    {hasVuln && (
                      <span title={`${lineVulns.length} issue(s)`}>
                        {SEVERITY_ICON[severity]}
                      </span>
                    )}
                  </span>

                  {/* Code content */}
                  <span className="flex-1 pl-2 pr-4">
                    {line.map((token, tokenIndex) => (
                      <span key={tokenIndex} {...getTokenProps({ token })} />
                    ))}
                  </span>
                </div>
              );
            })}
          </pre>
        )}
      </Highlight>
    </div>
  );
}
