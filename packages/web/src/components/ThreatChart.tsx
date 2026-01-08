import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface ThreatChartProps {
  data: {
    spoofing: number;
    tampering: number;
    repudiation: number;
    information_disclosure: number;
    denial_of_service: number;
    elevation_of_privilege: number;
  };
}

const STRIDE_LABELS: Record<string, string> = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  information_disclosure: 'Info Disclosure',
  denial_of_service: 'Denial of Service',
  elevation_of_privilege: 'Privilege Escalation',
};

const COLORS = ['#DC2626', '#F97316', '#EAB308', '#22C55E', '#3B82F6', '#8B5CF6'];

export default function ThreatChart({ data }: ThreatChartProps) {
  const chartData = Object.entries(data)
    .filter(([_, value]) => value > 0)
    .map(([key, value]) => ({
      name: STRIDE_LABELS[key] || key,
      value,
    }));

  if (chartData.length === 0) {
    return (
      <div className="h-64 flex items-center justify-center text-gray-500">
        No threats identified
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={280}>
      <PieChart>
        <Pie
          data={chartData}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={90}
          paddingAngle={2}
          dataKey="value"
        >
          {chartData.map((_, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            backgroundColor: '#1F2937',
            border: 'none',
            borderRadius: '8px',
            color: '#fff',
          }}
        />
        <Legend
          layout="horizontal"
          align="center"
          verticalAlign="bottom"
          wrapperStyle={{ color: '#9CA3AF', fontSize: '12px' }}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
