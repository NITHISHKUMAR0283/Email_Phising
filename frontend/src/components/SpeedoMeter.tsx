import React from 'react';

interface SpeedoMeterProps {
  score: number; // 0-1
  label?: string;
}

const SpeedoMeter: React.FC<SpeedoMeterProps> = ({ score, label = 'RISK_LEVEL' }) => {
  const percentage = Math.min(100, Math.max(0, score * 100));
  const angle = (percentage / 100) * 270 - 135; // -135 to 135 degrees

  // Determine color based on score
  let color = '#10b981'; // green
  let glowColor = 'rgba(16, 185, 129, 0.5)';
  if (percentage >= 80) {
    color = '#ef4444'; // red
    glowColor = 'rgba(239, 68, 68, 0.8)';
  } else if (percentage >= 60) {
    color = '#f97316'; // orange
    glowColor = 'rgba(249, 115, 22, 0.6)';
  } else if (percentage >= 40) {
    color = '#eab308'; // yellow
    glowColor = 'rgba(234, 179, 8, 0.5)';
  }

  return (
    <div className="flex flex-col items-center justify-center w-full">
      <svg
        viewBox="0 0 300 300"
        className="w-80 h-80 drop-shadow-2xl"
        style={{ filter: `drop-shadow(0 0 30px ${glowColor})` }}
      >
        {/* Outer glow circle */}
        <circle
          cx="150"
          cy="150"
          r="140"
          fill="none"
          stroke={color}
          strokeWidth="1"
          opacity="0.2"
          style={{
            animation: 'pulse 2s ease-in-out infinite',
          }}
        />

        {/* Main meter background circle */}
        <circle cx="150" cy="150" r="130" fill="#0a0e27" stroke="#1e293b" strokeWidth="2" />

        {/* Meter arc - background */}
        <path
          d="M 30 150 A 120 120 0 0 1 270 150"
          fill="none"
          stroke="#1e293b"
          strokeWidth="20"
          strokeLinecap="round"
        />

        {/* Red zone (80-100%) */}
        <path
          d="M 30 150 A 120 120 0 0 1 80 40"
          fill="none"
          stroke="#dc2626"
          strokeWidth="20"
          strokeLinecap="round"
          opacity="0.3"
        />

        {/* Orange zone (60-80%) */}
        <path
          d="M 80 40 A 120 120 0 0 1 150 30"
          fill="none"
          stroke="#f97316"
          strokeWidth="20"
          strokeLinecap="round"
          opacity="0.3"
        />

        {/* Yellow zone (40-60%) */}
        <path
          d="M 150 30 A 120 120 0 0 1 220 40"
          fill="none"
          stroke="#eab308"
          strokeWidth="20"
          strokeLinecap="round"
          opacity="0.3"
        />

        {/* Green zone (0-40%) */}
        <path
          d="M 220 40 A 120 120 0 0 1 270 150"
          fill="none"
          stroke="#10b981"
          strokeWidth="20"
          strokeLinecap="round"
          opacity="0.3"
        />

        {/* Meter arc - active fill */}
        <path
          d="M 30 150 A 120 120 0 0 1 270 150"
          fill="none"
          stroke={color}
          strokeWidth="20"
          strokeLinecap="round"
          strokeDasharray={`${(percentage / 100) * (Math.PI * 240)} ${Math.PI * 240}`}
          style={{
            transition: 'stroke-dasharray 0.5s ease',
            filter: `drop-shadow(0 0 15px ${glowColor})`,
          }}
        />

        {/* Center circle with glow */}
        <circle
          cx="150"
          cy="150"
          r="75"
          fill="#0f1419"
          stroke={color}
          strokeWidth="2"
          opacity="0.8"
          style={{
            filter: `drop-shadow(0 0 20px ${glowColor})`,
          }}
        />

        {/* Needle */}
        <line
          x1="150"
          y1="150"
          x2={150 + Math.cos((angle * Math.PI) / 180) * 65}
          y2={150 + Math.sin((angle * Math.PI) / 180) * 65}
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          style={{
            transition: 'transform 0.5s ease',
            filter: `drop-shadow(0 0 10px ${glowColor})`,
          }}
        />

        {/* Needle pivot */}
        <circle cx="150" cy="150" r="6" fill={color} />

        {/* Scale markers */}
        {[0, 20, 40, 60, 80, 100].map((val) => {
          const markerAngle = (val / 100) * 270 - 135;
          const x1 = 150 + Math.cos((markerAngle * Math.PI) / 180) * 110;
          const y1 = 150 + Math.sin((markerAngle * Math.PI) / 180) * 110;
          const x2 = 150 + Math.cos((markerAngle * Math.PI) / 180) * 120;
          const y2 = 150 + Math.sin((markerAngle * Math.PI) / 180) * 120;

          return (
            <g key={val}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#64748b" strokeWidth="2" />
              <text
                x={150 + Math.cos((markerAngle * Math.PI) / 180) * 95}
                y={150 + Math.sin((markerAngle * Math.PI) / 180) * 95}
                textAnchor="middle"
                dy="0.3em"
                fill="#94a3b8"
                fontSize="12"
                fontFamily="monospace"
              >
                {val}
              </text>
            </g>
          );
        })}

        {/* Center number display */}
        <text
          x="150"
          y="145"
          textAnchor="middle"
          fill={color}
          fontSize="48"
          fontWeight="bold"
          fontFamily="monospace"
          style={{ textShadow: `0 0 10px ${glowColor}` }}
        >
          {percentage.toFixed(0)}
        </text>
        <text
          x="150"
          y="170"
          textAnchor="middle"
          fill="#64748b"
          fontSize="14"
          fontFamily="monospace"
        >
          %
        </text>
      </svg>

      {/* Label below */}
      <div className="mt-4 text-center font-mono">
        <div className="text-sm" style={{ color: glowColor }}>
          {label}
        </div>
        <div
          className="text-lg font-bold"
          style={{
            color: color,
            textShadow: `0 0 10px ${glowColor}`,
          }}
        >
          {percentage >= 80 ? '🔴 CRITICAL' : percentage >= 60 ? '🟠 HIGH' : percentage >= 40 ? '🟡 MEDIUM' : '🟢 SAFE'}
        </div>
      </div>

      <style>{`
        @keyframes pulse {
          0%, 100% { 
            stroke-width: 1;
            opacity: 0.2;
          }
          50% { 
            stroke-width: 2;
            opacity: 0.4;
          }
        }
      `}</style>
    </div>
  );
};

export default SpeedoMeter;
