interface SeverityStatsProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
}

export default function SeverityStats({ critical, high, medium, low, info = 0 }: SeverityStatsProps) {
  const stats = [
    { label: 'Critical', value: critical, color: 'bg-red-500', textColor: 'text-red-500' },
    { label: 'High', value: high, color: 'bg-orange-500', textColor: 'text-orange-500' },
    { label: 'Medium', value: medium, color: 'bg-yellow-500', textColor: 'text-yellow-500' },
    { label: 'Low', value: low, color: 'bg-green-500', textColor: 'text-green-500' },
    { label: 'Info', value: info, color: 'bg-gray-500', textColor: 'text-gray-500' },
  ];

  return (
    <div className="flex gap-4 flex-wrap">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="bg-gray-800 rounded-lg p-4 flex items-center gap-3 min-w-[120px]"
        >
          <div className={`w-3 h-3 rounded-full ${stat.color}`} />
          <div>
            <p className={`text-2xl font-bold ${stat.textColor}`}>{stat.value}</p>
            <p className="text-xs text-gray-400">{stat.label}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
