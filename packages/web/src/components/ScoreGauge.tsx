interface ScoreGaugeProps {
  score: number;
  size?: number;
}

export default function ScoreGauge({ score, size = 200 }: ScoreGaugeProps) {
  const radius = 45;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const offset = circumference - progress;

  // Color based on score
  const getColor = () => {
    if (score >= 80) return '#22C55E'; // Green
    if (score >= 50) return '#EAB308'; // Yellow
    return '#DC2626'; // Red
  };

  const getLabel = () => {
    if (score >= 80) return 'Good';
    if (score >= 50) return 'Fair';
    return 'Poor';
  };

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox="0 0 100 100">
        {/* Background circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke="#374151"
          strokeWidth="8"
        />
        {/* Progress circle */}
        <circle
          cx="50"
          cy="50"
          r={radius}
          fill="none"
          stroke={getColor()}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 50 50)"
          className="score-gauge"
        />
        {/* Score text */}
        <text
          x="50"
          y="45"
          textAnchor="middle"
          className="fill-white text-2xl font-bold"
          style={{ fontSize: '24px' }}
        >
          {score}
        </text>
        <text
          x="50"
          y="62"
          textAnchor="middle"
          className="fill-gray-400"
          style={{ fontSize: '10px' }}
        >
          / 100
        </text>
      </svg>
      <span
        className="mt-2 text-sm font-medium"
        style={{ color: getColor() }}
      >
        {getLabel()}
      </span>
    </div>
  );
}
