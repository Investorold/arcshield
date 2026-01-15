import { useState, useMemo, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, LayoutGrid, Keyboard } from 'lucide-react';
import { useScan } from '../hooks/useScans';
import FileTree from '../components/CodeViewer/FileTree';
import CodeViewer, { detectLanguage } from '../components/CodeViewer/CodeViewer';
import VulnDetailPanel from '../components/CodeViewer/VulnDetailPanel';
import { useCodeNavigation } from '../hooks/useCodeNavigation';
import type { Vulnerability, ArcVulnerability } from '../types';

type VulnItem = Vulnerability | ArcVulnerability;

export default function ReportIDE() {
  const { id } = useParams<{ id: string }>();
  const { scan, loading, error } = useScan(id);

  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [selectedVuln, setSelectedVuln] = useState<VulnItem | null>(null);
  const [showKeyboardHelp, setShowKeyboardHelp] = useState(false);

  // Combine all vulnerabilities
  const allVulnerabilities = useMemo(() => {
    if (!scan) return [];
    return [
      ...(scan.vulnerabilities?.vulnerabilities || []),
      ...(scan.arcVulnerabilities || []),
      ...(scan.smartContractVulnerabilities || []),
      ...(scan.genLayerVulnerabilities || []),
    ];
  }, [scan]);

  // Vulnerabilities for selected file
  const fileVulnerabilities = useMemo(() => {
    if (!selectedFile) return [];
    return allVulnerabilities.filter((v) => v.filePath === selectedFile);
  }, [allVulnerabilities, selectedFile]);

  // Keyboard navigation
  useCodeNavigation({
    vulnerabilities: fileVulnerabilities,
    selectedVuln,
    onSelectVuln: setSelectedVuln,
    enabled: true,
  });

  // Auto-select first file if none selected
  useEffect(() => {
    if (!selectedFile && allVulnerabilities.length > 0) {
      setSelectedFile(allVulnerabilities[0].filePath);
    }
  }, [selectedFile, allVulnerabilities]);

  // When vulnerability is selected, ensure its file is selected
  useEffect(() => {
    if (selectedVuln && selectedVuln.filePath !== selectedFile) {
      setSelectedFile(selectedVuln.filePath);
    }
  }, [selectedVuln, selectedFile]);

  // Mock code content (in real implementation, this would come from the scan)
  const codeContent = useMemo(() => {
    if (!selectedFile || !fileVulnerabilities.length) return '';

    // Generate placeholder code with line numbers matching vulnerabilities
    const maxLine = Math.max(...fileVulnerabilities.map((v) => v.lineNumber)) + 5;
    const lines: string[] = [];

    for (let i = 1; i <= maxLine; i++) {
      const vuln = fileVulnerabilities.find((v) => v.lineNumber === i);
      if (vuln && vuln.codeSnippet) {
        // Use the code snippet from the vulnerability
        lines.push(vuln.codeSnippet.split('\n')[0] || `// Line ${i}`);
      } else {
        lines.push(`// Line ${i} - placeholder`);
      }
    }

    return lines.join('\n');
  }, [selectedFile, fileVulnerabilities]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-gray-400">Loading report...</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex items-center justify-center h-screen bg-gray-900">
        <div className="text-center">
          <p className="text-red-400 mb-4">Failed to load report</p>
          <Link to="/" className="text-arc-purple hover:underline">
            Go back to dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col bg-gray-900">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center gap-4">
          <Link
            to={`/report/${id}`}
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span className="text-sm">Back to Report</span>
          </Link>
          <div className="h-4 w-px bg-gray-700" />
          <h1 className="text-sm font-medium text-white">IDE View</h1>
          <span className="text-xs text-gray-500 font-mono truncate max-w-xs">
            {scan.target}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">
            {allVulnerabilities.length} issues
          </span>
          <button
            onClick={() => setShowKeyboardHelp(true)}
            className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
            title="Keyboard shortcuts"
          >
            <Keyboard className="w-4 h-4" />
          </button>
          <Link
            to={`/report/${id}`}
            className="p-1.5 rounded hover:bg-gray-700 text-gray-400 hover:text-white"
            title="Standard view"
          >
            <LayoutGrid className="w-4 h-4" />
          </Link>
        </div>
      </header>

      {/* Main content - 3 panel layout */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left panel - File tree */}
        <div className="w-64 flex-shrink-0 bg-gray-800 border-r border-gray-700 overflow-auto">
          <div className="p-2 border-b border-gray-700">
            <h2 className="text-xs font-medium text-gray-400 uppercase tracking-wider">
              Files
            </h2>
          </div>
          <FileTree
            vulnerabilities={allVulnerabilities}
            selectedFile={selectedFile}
            onSelectFile={setSelectedFile}
          />
        </div>

        {/* Center panel - Code viewer */}
        <div className="flex-1 overflow-hidden">
          {selectedFile ? (
            <CodeViewer
              code={codeContent}
              language={detectLanguage(selectedFile)}
              vulnerabilities={fileVulnerabilities}
              selectedVulnId={selectedVuln?.id || null}
              onSelectVuln={setSelectedVuln}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-gray-500">
              Select a file from the tree
            </div>
          )}
        </div>

        {/* Right panel - Vulnerability details */}
        <div className="w-80 flex-shrink-0 border-l border-gray-700 overflow-hidden">
          <VulnDetailPanel
            vulnerability={selectedVuln}
            allVulnerabilities={fileVulnerabilities}
            onClose={() => setSelectedVuln(null)}
            onNavigate={setSelectedVuln}
          />
        </div>
      </div>

      {/* Keyboard shortcuts modal */}
      {showKeyboardHelp && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-96 border border-gray-700">
            <h3 className="text-lg font-semibold mb-4">Keyboard Shortcuts</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Next vulnerability</span>
                <span className="font-mono bg-gray-700 px-2 py-0.5 rounded">j / ↓</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Previous vulnerability</span>
                <span className="font-mono bg-gray-700 px-2 py-0.5 rounded">k / ↑</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">First vulnerability</span>
                <span className="font-mono bg-gray-700 px-2 py-0.5 rounded">g</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Last vulnerability</span>
                <span className="font-mono bg-gray-700 px-2 py-0.5 rounded">G</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Clear selection</span>
                <span className="font-mono bg-gray-700 px-2 py-0.5 rounded">Esc</span>
              </div>
            </div>
            <button
              onClick={() => setShowKeyboardHelp(false)}
              className="w-full mt-6 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-white"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
