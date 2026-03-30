import React from 'react';

interface RiskGaugeProps {
  score: number; // 0-1
  size?: number;
  showLabel?: boolean;
}

export default function RiskGauge({ score, size = 200, showLabel = true }: RiskGaugeProps) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference * (1 - Math.clamp(score, 0, 1));

  // Determine color based on score
  let color = '#22c55e'; // Green
  if (score > 0.7) color = '#ef4444'; // Red
  else if (score > 0.45) color = '#eab308'; // Yellow
  else if (score > 0.3) color = '#f97316'; // Orange

  const percentage = Math.round(score * 100);

  return (
    <div className="flex flex-col items-center justify-center">
      <style>{`
        @keyframes pulse-glow {
          0%, 100% { filter: drop-shadow(0 0 8px rgba(${score > 0.7 ? '239,68,68' : score > 0.45 ? '234,179,8' : '34,197,94'}, 0.6)); }
          50% { filter: drop-shadow(0 0 20px rgba(${score > 0.7 ? '239,68,68' : score > 0.45 ? '234,179,8' : '34,197,94'}, 0.8)); }
        }
        .risk-gauge { animation: pulse-glow 2s ease-in-out infinite; }
      `}</style>
      
      <svg width={size} height={size} className="risk-gauge transform -rotate-90">
        {/* Background circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.1)"
          strokeWidth="8"
        />
        
        {/* Gradient definition for animated stroke */}
        <defs>
          <linearGradient id="riskGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#fbbf24" />
            <stop offset="50%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>
        
        {/* Progress circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{
            transition: 'stroke-dashoffset 0.5s ease, stroke 0.5s ease',
          }}
        />
      </svg>

      {showLabel && (
        <div className="text-center mt-4">
          <div className="text-4xl font-bold text-white" style={{ color }}>
            {percentage}%
          </div>
          <div className={`text-sm font-semibold ${
            score > 0.7 ? 'text-red-400' :
            score > 0.45 ? 'text-yellow-400' :
            score > 0.3 ? 'text-orange-400' :
            'text-green-400'
          }`}>
            {score > 0.7 ? 'CRITICAL' :
             score > 0.45 ? 'WARNING' :
             score > 0.3 ? 'MEDIUM' :
             'SAFE'}
          </div>
        </div>
      )}
    </div>
  );
}

// Helper function since Math.clamp doesn't exist in JS
declare global {
  interface Math {
    clamp(value: number, min: number, max: number): number;
  }
}

if (!Math.clamp) {
  Math.clamp = function(value: number, min: number, max: number): number {
    return Math.max(min, Math.min(max, value));
  };
}
