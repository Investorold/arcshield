import type { Vulnerability, ArcVulnerability, Severity } from '../types';

interface VulnTableProps {
  vulnerabilities: (Vulnerability | ArcVulnerability)[];
  title?: string;
}

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', label: 'Critical' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', label: 'High' },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', label: 'Medium' },
  low: { color: 'text-green-500', bg: 'bg-green-500/10', label: 'Low' },
  info: { color: 'text-gray-500', bg: 'bg-gray-500/10', label: 'Info' },
};

export default function VulnTable({ vulnerabilities, title = 'Vulnerabilities' }: VulnTableProps) {
  if (vulnerabilities.length === 0) {
    return (
      <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-6">
        <div className="flex items-center gap-3 mb-2">
          <h3 className="text-lg font-semibold">{title}</h3>
          <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded">Actual Code Issues</span>
        </div>
        <p className="text-sm text-gray-400 mb-4">
          Vulnerabilities are actual security flaws found in your code that need to be fixed.
        </p>
        <div className="flex items-center justify-center py-8 bg-green-900/10 rounded-lg border border-green-500/20">
          <div className="text-center">
            <div className="text-4xl mb-2">&#10003;</div>
            <p className="text-green-400 font-medium">No vulnerabilities found</p>
            <p className="text-sm text-gray-500 mt-1">Your code passed security analysis</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-red-900/10 border border-red-500/30 rounded-lg overflow-hidden">
      <div className="p-4 border-b border-red-500/20">
        <div className="flex items-center gap-3">
          <h3 className="text-lg font-semibold">{title}</h3>
          <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">Actual Code Issues</span>
        </div>
        <p className="text-sm text-gray-400 mt-1">
          These are real security flaws in your code that should be addressed.
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-700/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Severity</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">ID</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Title</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Location</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">CWE</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {vulnerabilities.map((vuln) => {
              const config = SEVERITY_CONFIG[vuln.severity];
              return (
                <tr key={vuln.id} className="hover:bg-gray-700/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${config.color} ${config.bg}`}>
                      {config.label}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-gray-300">{vuln.id}</td>
                  <td className="px-4 py-3 text-sm text-white">{vuln.title}</td>
                  <td className="px-4 py-3 text-sm text-gray-400 font-mono">
                    {vuln.filePath}:{vuln.lineNumber}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">{vuln.cweId || '-'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
