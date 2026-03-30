import React from 'react';

interface CircularRiskScoreProps {
  score: number;
  riskLevel: string;
}

const CircularRiskScore: React.FC<CircularRiskScoreProps> = ({ score, riskLevel }) => {
  const percentage = Math.round(score * 100);
  const circumference = 2 * Math.PI * 45; // radius = 45
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  const getColors = () => {
    if (percentage >= 80) return { outer: '#dc2626', inner: '#7f1d1d' };
    if (percentage >= 65) return { outer: '#ea580c', inner: '#7c2d12' };
    if (percentage >= 45) return { outer: '#f59e0b', inner: '#78350f' };
    return { outer: '#10b981', inner: '#064e3b' };
  };

  const colors = getColors();

  return (
    <div className="flex flex-col items-center justify-center py-8">
      <div className="relative w-32 h-32">
        {/* Outer glow */}
        <div
          className="absolute inset-0 rounded-full blur-xl opacity-50"
          style={{ backgroundColor: colors.outer }}
        ></div>

        {/* SVG Circle Progress */}
        <svg
          className="absolute inset-0 w-full h-full transform -rotate-90"
          viewBox="0 0 100 100"
        >
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke="#374151"
            strokeWidth="2"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r="45"
            fill="none"
            stroke={colors.outer}
            strokeWidth="3"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.5s ease-in-out',
              filter: 'drop-shadow(0 0 8px rgba(220, 38, 38, 0.5))',
            }}
          />
        </svg>

        {/* Score text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold text-white">{percentage}%</div>
          <div className="text-xs text-gray-300 mt-1 uppercase tracking-widest">Risk</div>
        </div>
      </div>

      {/* Risk level label */}
      <div className="mt-6 text-center">
        <div
          className="px-6 py-3 rounded-lg font-bold text-lg inline-block"
          style={{
            backgroundColor:
              percentage >= 80
                ? '#7f1d1d'
                : percentage >= 65
                ? '#7c2d12'
                : percentage >= 45
                ? '#78350f'
                : '#064e3b',
            color: colors.outer,
            border: `2px solid ${colors.outer}`,
            textShadow: `0 0 10px ${colors.outer}33`,
          }}
        >
          {riskLevel || 'ANALYZING...'}
        </div>
      </div>
    </div>
  );
};

export default CircularRiskScore;
