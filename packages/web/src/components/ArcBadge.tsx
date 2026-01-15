import { Trophy, AlertTriangle } from 'lucide-react';

interface ArcBadgeProps {
  eligible: boolean;
  reason?: string;
}

export default function ArcBadge({ eligible, reason }: ArcBadgeProps) {
  return (
    <div className={`p-4 rounded-lg border ${
      eligible
        ? 'bg-green-500/10 border-green-500/30'
        : 'bg-red-500/10 border-red-500/30'
    }`}>
      <div className="flex items-center gap-3">
        {eligible
          ? <Trophy className="w-8 h-8 text-yellow-400" aria-hidden="true" />
          : <AlertTriangle className="w-8 h-8 text-red-400" aria-hidden="true" />
        }
        <div>
          <h4 className={`font-semibold ${eligible ? 'text-green-400' : 'text-red-400'}`}>
            {eligible ? 'Eligible for ArcShield Verified Badge' : 'Not Eligible for Badge'}
          </h4>
          <p className="text-sm text-gray-400 mt-1">
            {eligible
              ? 'This project meets the security requirements for the ArcShield Verified badge.'
              : reason || 'Critical or high severity vulnerabilities must be resolved.'}
          </p>
        </div>
      </div>
    </div>
  );
}
