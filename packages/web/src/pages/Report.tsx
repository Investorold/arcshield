import { useParams, Link } from 'react-router-dom';
import { useScan } from '../hooks/useScans';
import ScoreGauge from '../components/ScoreGauge';
import SeverityStats from '../components/SeverityStats';
import ThreatChart from '../components/ThreatChart';
import VulnTable from '../components/VulnTable';
import ArcBadge from '../components/ArcBadge';

export default function Report() {
  const { id } = useParams<{ id: string }>();
  const { scan, loading, error } = useScan(id);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-400">Loading report...</div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400">
        Error: {error || 'Report not found'}
        <Link to="/" className="block mt-4 text-arc-purple hover:underline">
          ← Back to Dashboard
        </Link>
      </div>
    );
  }

  // Combine all vulnerabilities for display
  const allVulnerabilities = [
    ...(scan.vulnerabilities?.vulnerabilities || []),
    ...(scan.arcVulnerabilities || []),
    ...(scan.smartContractVulnerabilities || []),
  ];

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <Link to="/" className="text-gray-400 hover:text-white text-sm mb-2 inline-block">
            ← Back to Dashboard
          </Link>
          <h1 className="text-3xl font-bold">Security Report</h1>
          <p className="text-gray-400 mt-1 font-mono">{scan.target}</p>
        </div>
        <div className="text-right text-sm text-gray-400">
          <p>Scan ID: {scan.id}</p>
          <p>{new Date(scan.timestamp).toLocaleString()}</p>
          <p>Duration: {(scan.duration / 1000).toFixed(1)}s</p>
          <p>Cost: ${scan.cost.toFixed(4)}</p>
        </div>
      </div>

      {/* Score and Badge */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Security Score</h2>
          <div className="flex items-center gap-8">
            <ScoreGauge score={scan.score} />
            <div>
              <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Vulnerability Count</p>
              <SeverityStats
                critical={scan.summary.critical}
                high={scan.summary.high}
                medium={scan.summary.medium}
                low={scan.summary.low}
                info={scan.summary.info}
              />
              <p className="text-sm text-gray-400 mt-4">
                Total Issues: {scan.summary.totalIssues}
              </p>
              {scan.summary.totalIssues === 0 && (
                <p className="text-sm text-green-400 mt-2">No actual code vulnerabilities found</p>
              )}
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Badge Status</h2>
          <ArcBadge eligible={scan.badge.eligible} reason={scan.badge.reason} />
        </div>
      </div>

      {/* Threat Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Threat Distribution (STRIDE)</h2>
          <ThreatChart data={scan.threatModel.summary.byCategory} />
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Architecture</h2>
          <div className="space-y-4">
            <div>
              <p className="text-gray-400 text-sm">Application Type</p>
              <p className="font-medium">{scan.assessment.architecture.type}</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Frameworks</p>
              <div className="flex flex-wrap gap-2 mt-1">
                {scan.assessment.architecture.frameworks.map((fw) => (
                  <span key={fw} className="bg-gray-700 px-2 py-1 rounded text-sm">
                    {fw}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Files Analyzed</p>
              <p className="font-medium">{scan.assessment.fileCount} files ({scan.assessment.totalLines} lines)</p>
            </div>
            <div>
              <p className="text-gray-400 text-sm">Entry Points</p>
              <p className="font-medium">{scan.assessment.architecture.entryPoints.length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Model - Theoretical Risks */}
      <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6 mb-8">
        <div className="flex items-center gap-3 mb-2">
          <h2 className="text-lg font-semibold">Threat Model (STRIDE Analysis)</h2>
          <span className="text-xs bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded">Theoretical</span>
        </div>
        <p className="text-sm text-gray-400 mb-4 border-l-2 border-blue-500/30 pl-3">
          These are theoretical attack scenarios based on your architecture, not actual vulnerabilities in your code.
          Every project using similar patterns would have these same considerations.
          Your security controls may already address these risks.
        </p>
        <div className="space-y-3 max-h-96 overflow-y-auto">
          {scan.threatModel.threats.map((threat) => (
            <div key={threat.id} className="bg-gray-700/30 border border-gray-600/50 rounded-lg p-4">
              <div className="flex items-start justify-between">
                <div>
                  <span className={`text-xs px-2 py-0.5 rounded mr-2 ${
                    threat.severity === 'critical' ? 'bg-red-500/10 text-red-400/80' :
                    threat.severity === 'high' ? 'bg-orange-500/10 text-orange-400/80' :
                    threat.severity === 'medium' ? 'bg-yellow-500/10 text-yellow-400/80' :
                    'bg-green-500/10 text-green-400/80'
                  }`}>
                    {threat.severity.toUpperCase()} RISK
                  </span>
                  <span className="text-xs text-gray-500">{threat.id}</span>
                </div>
                <span className="text-xs bg-gray-600/50 px-2 py-0.5 rounded text-gray-300">
                  {threat.category.replace('_', ' ').toUpperCase()}
                </span>
              </div>
              <h3 className="font-medium mt-2 text-gray-200">{threat.title}</h3>
              <p className="text-sm text-gray-400 mt-1">{threat.description}</p>
            </div>
          ))}
        </div>
        {scan.threatModel.threats.length === 0 && (
          <p className="text-gray-500 text-center py-4">No significant threat patterns identified</p>
        )}
      </div>

      {/* Vulnerabilities */}
      <VulnTable
        vulnerabilities={allVulnerabilities}
        title={`Vulnerabilities (${allVulnerabilities.length})`}
      />

      {/* Arc-Specific Issues */}
      {scan.arcVulnerabilities && scan.arcVulnerabilities.length > 0 && (
        <div className="mt-8">
          <VulnTable
            vulnerabilities={scan.arcVulnerabilities}
            title={`Arc-Specific Issues (${scan.arcVulnerabilities.length})`}
          />
        </div>
      )}
    </div>
  );
}
