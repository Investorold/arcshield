import { useState } from 'react';
import { X, Copy, Check, ChevronUp, ChevronDown, ExternalLink } from 'lucide-react';
import type { Vulnerability, ArcVulnerability, Severity } from '../../types';

type VulnItem = Vulnerability | ArcVulnerability;

interface VulnDetailPanelProps {
  vulnerability: VulnItem | null;
  allVulnerabilities: VulnItem[];
  onClose: () => void;
  onNavigate: (vuln: VulnItem) => void;
}

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20', label: 'Critical' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20', label: 'High' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20', label: 'Medium' },
  low: { color: 'text-green-400', bg: 'bg-green-500/20', label: 'Low' },
  info: { color: 'text-gray-400', bg: 'bg-gray-500/20', label: 'Info' },
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1.5 rounded hover:bg-gray-700 transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-4 h-4 text-green-400" />
      ) : (
        <Copy className="w-4 h-4 text-gray-400" />
      )}
    </button>
  );
}

export default function VulnDetailPanel({
  vulnerability,
  allVulnerabilities,
  onClose,
  onNavigate,
}: VulnDetailPanelProps) {
  if (!vulnerability) {
    return (
      <div className="h-full flex items-center justify-center text-gray-500 text-sm p-4 text-center">
        <div>
          <p>Select a vulnerability</p>
          <p className="text-xs mt-1">Click on highlighted lines in the code</p>
        </div>
      </div>
    );
  }

  const config = SEVERITY_CONFIG[vulnerability.severity];
  const currentIndex = allVulnerabilities.findIndex((v) => v.id === vulnerability.id);
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < allVulnerabilities.length - 1;

  const generateAIPrompt = () => {
    return `I have a security vulnerability in my code that I need help fixing.

**Vulnerability Details:**
- Type: ${vulnerability.title}
- Severity: ${vulnerability.severity.toUpperCase()}
- Location: ${vulnerability.filePath}:${vulnerability.lineNumber}
- CWE: ${vulnerability.cweId || 'N/A'}

**Description:**
${vulnerability.description}

**Code with the issue:**
\`\`\`
${vulnerability.codeSnippet || 'See file at line ' + vulnerability.lineNumber}
\`\`\`

**Recommended Fix:**
${vulnerability.remediation || 'Review and fix the security issue'}

Please provide:
1. The fixed code
2. An explanation of what was wrong
3. How the fix prevents the vulnerability`;
  };

  return (
    <div className="h-full flex flex-col bg-gray-800">
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${config.color} ${config.bg}`}>
            {config.label}
          </span>
          <span className="text-xs text-gray-500">{vulnerability.id}</span>
        </div>
        <div className="flex items-center gap-1">
          {/* Navigation */}
          <button
            onClick={() => hasPrev && onNavigate(allVulnerabilities[currentIndex - 1])}
            disabled={!hasPrev}
            className="p-1 rounded hover:bg-gray-700 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Previous vulnerability (k)"
          >
            <ChevronUp className="w-4 h-4" />
          </button>
          <span className="text-xs text-gray-500 px-1">
            {currentIndex + 1}/{allVulnerabilities.length}
          </span>
          <button
            onClick={() => hasNext && onNavigate(allVulnerabilities[currentIndex + 1])}
            disabled={!hasNext}
            className="p-1 rounded hover:bg-gray-700 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Next vulnerability (j)"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
          <button onClick={onClose} className="p-1 rounded hover:bg-gray-700 ml-2" title="Close">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-4 space-y-4">
        {/* Title */}
        <div>
          <h3 className="font-semibold text-white">{vulnerability.title}</h3>
          <p className="text-sm text-gray-400 font-mono mt-1">
            {vulnerability.filePath}:{vulnerability.lineNumber}
          </p>
        </div>

        {/* CWE */}
        {vulnerability.cweId && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-gray-500">CWE:</span>
            <a
              href={`https://cwe.mitre.org/data/definitions/${vulnerability.cweId.replace('CWE-', '')}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-arc-purple hover:underline flex items-center gap-1"
            >
              {vulnerability.cweId}
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        )}

        {/* Third-party indicator */}
        {vulnerability.isThirdParty && (
          <div className="bg-purple-500/10 border border-purple-500/20 rounded p-2">
            <span className="text-purple-400 text-sm">📦 Third-party code</span>
            <p className="text-xs text-purple-300 mt-1">
              Source: {vulnerability.thirdPartySource || 'dependency'}
            </p>
          </div>
        )}

        {/* Description */}
        <div>
          <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-1">Description</h4>
          <p className="text-sm text-gray-300">{vulnerability.description}</p>
        </div>

        {/* Code Snippet */}
        {vulnerability.codeSnippet && (
          <div>
            <div className="flex items-center justify-between mb-1">
              <h4 className="text-xs text-gray-500 uppercase tracking-wider">Code</h4>
              <CopyButton text={vulnerability.codeSnippet} />
            </div>
            <pre className="bg-gray-900 rounded p-3 text-xs text-gray-300 overflow-x-auto font-mono">
              {vulnerability.codeSnippet}
            </pre>
          </div>
        )}

        {/* Remediation */}
        {vulnerability.remediation && (
          <div>
            <h4 className="text-xs text-gray-500 uppercase tracking-wider mb-1">How to Fix</h4>
            <p className="text-sm text-gray-300">{vulnerability.remediation}</p>
          </div>
        )}

        {/* AI Fix Prompt */}
        <div className="border-t border-gray-700 pt-4">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium text-purple-400">🤖 AI Fix Prompt</h4>
            <button
              onClick={() => navigator.clipboard.writeText(generateAIPrompt())}
              className="px-3 py-1 bg-purple-500/20 hover:bg-purple-500/30 text-purple-400 rounded text-xs font-medium transition-colors"
            >
              Copy Prompt
            </button>
          </div>
          <p className="text-xs text-gray-500">
            Copy and paste into ChatGPT, Claude, or your AI assistant.
          </p>
        </div>
      </div>
    </div>
  );
}
