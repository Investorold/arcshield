import { Link } from 'react-router-dom';
import { useScans } from '../hooks/useScans';
import ScoreGauge from '../components/ScoreGauge';
import SeverityStats from '../components/SeverityStats';

export default function Home() {
  const { scans, loading, error } = useScans();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-400">Loading scans...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-red-400">
        Error: {error}
      </div>
    );
  }

  const latestScan = scans[0];

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-gray-400 mt-1">Overview of your security scans</p>
        </div>
        <Link
          to="/scan"
          className="bg-arc-purple hover:bg-arc-purple/80 text-white px-4 py-2 rounded-lg transition-colors"
        >
          New Scan
        </Link>
      </div>

      {scans.length === 0 ? (
        <div className="bg-gray-800 rounded-lg p-12 text-center">
          <span className="text-6xl">🔍</span>
          <h2 className="text-xl font-semibold mt-4">No scans yet</h2>
          <p className="text-gray-400 mt-2">Run your first security scan to see results here</p>
          <Link
            to="/scan"
            className="inline-block mt-4 bg-arc-purple hover:bg-arc-purple/80 text-white px-6 py-2 rounded-lg transition-colors"
          >
            Start Scanning
          </Link>
        </div>
      ) : (
        <>
          {/* Latest Scan Summary */}
          <div className="bg-gray-800 rounded-lg p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Latest Scan</h2>
              <Link
                to={`/report/${latestScan.id}`}
                className="text-arc-purple hover:underline text-sm"
              >
                View Full Report →
              </Link>
            </div>

            <div className="flex items-center gap-8">
              <ScoreGauge score={latestScan.score} size={150} />

              <div className="flex-1">
                <p className="text-gray-400 text-sm">Target</p>
                <p className="font-mono text-lg">{latestScan.target}</p>
                <p className="text-gray-400 text-sm mt-2">Scanned</p>
                <p className="text-sm">{new Date(latestScan.timestamp).toLocaleString()}</p>
              </div>

              <div>
                <p className="text-gray-400 text-sm mb-2">Issues Found</p>
                <SeverityStats
                  critical={latestScan.critical}
                  high={latestScan.high}
                  medium={latestScan.medium}
                  low={latestScan.low}
                />
              </div>
            </div>
          </div>

          {/* Scan History */}
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold">Scan History</h2>
            </div>
            <table className="w-full">
              <thead className="bg-gray-700/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Issues</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm">{scan.target}</td>
                    <td className="px-4 py-3">
                      <span className={`font-bold ${
                        scan.score >= 80 ? 'text-green-500' :
                        scan.score >= 50 ? 'text-yellow-500' : 'text-red-500'
                      }`}>
                        {scan.score}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      <span className="text-red-500">{scan.critical}C</span>
                      {' / '}
                      <span className="text-orange-500">{scan.high}H</span>
                      {' / '}
                      <span className="text-yellow-500">{scan.medium}M</span>
                      {' / '}
                      <span className="text-green-500">{scan.low}L</span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">
                      {new Date(scan.timestamp).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        to={`/report/${scan.id}`}
                        className="text-arc-purple hover:underline text-sm"
                      >
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
