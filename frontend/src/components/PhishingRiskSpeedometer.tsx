import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

/**
 * ============================================================================
 * PhishingRiskSpeedometer Component
 * ============================================================================
 * 
 * A forensic-grade semi-circular speedometer gauge for visualizing
 * phishing risk scores using Recharts PieChart.
 * 
 * Features:
 * - Semi-circular gauge (180° to 0°) with three color-coded risk zones
 * - Animated custom needle pointing to current risk score
 * - Responsive layout with proper vertical alignment
 * - Monospace numeric readout and risk badge
 * - Dark theme integration
 * 
 * @component
 * @example
 * <PhishingRiskSpeedometer riskScore={65} animationDuration={1000} />
 * 
 * ============================================================================
 */

interface PhishingRiskSpeedometerProps {
  /** Risk score as a percentage (0-100). Default: 0 */
  riskScore: number;
  /** Animation duration in milliseconds for needle movement. Default: 800 */
  animationDuration?: number;
  /** Optional className for the container. Default: '' */
  className?: string;
}

// Risk zone data: Safe (0-30%), Suspicious (31-70%), Critical (71-100%)
const RISK_ZONES = [
  { name: 'Safe', value: 30, fill: '#10b981' },      // Emerald-500
  { name: 'Suspicious', value: 40, fill: '#f59e0b' }, // Amber-500
  { name: 'Critical', value: 30, fill: '#ef4444' },   // Rose-500
];

/**
 * Utility: Clamp a value between min and max
 */
const clamp = (value: number, min: number, max: number): number => {
  return Math.max(min, Math.min(max, value));
};

/**
 * Utility: Get risk color based on score threshold
 */
const getRiskColor = (score: number): { primary: string; label: string } => {
  const clamped = clamp(score, 0, 100);
  if (clamped > 70) {
    return {
      primary: '#ef4444',      // Rose-500
      label: '🛑 CRITICAL',
    };
  } else if (clamped > 30) {
    return {
      primary: '#f59e0b',      // Amber-500
      label: '⚠️  SUSPICIOUS',
    };
  } else {
    return {
      primary: '#10b981',      // Emerald-500
      label: '✅ SAFE',
    };
  }
};

/**
 * Custom Needle Shape Component
 * Renders a sleek triangle needle pointing to the risk score angle
 */
interface CustomNeedleProps {
  cx?: number;
  cy?: number;
  outerRadius?: number;
  riskScore?: number;
}

const RADIAN = Math.PI / 180;

const CustomNeedle = ({
  cx = 140,
  cy = 140,
  outerRadius = 90,
  riskScore = 0,
}: CustomNeedleProps) => {
  // 180° is left (0%), 0° is right (100%)
  const angle = 180 - (riskScore / 100) * 180;
  const length = outerRadius - 10; // Needle extends nearly to arc edge
  const sin = Math.sin(-RADIAN * angle);
  const cos = Math.cos(-RADIAN * angle);
  const r = 6; // Center pivot radius

  // Calculate triangle needle points
  const x0 = cx;
  const y0 = cy;
  const xba = x0 + r * sin; // Back-left corner
  const yba = y0 - r * cos;
  const xbb = x0 - r * sin; // Back-right corner
  const ybb = y0 + r * cos;
  const xp = x0 + length * cos; // Needle tip
  const yp = y0 + length * sin;

  return (
    <g>
      {/* Center Pivot Circle */}
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="#e2e8f0"
        filter="drop-shadow(0 0 3px rgba(0,0,0,0.5))"
      />
      
      {/* Triangle Needle - sleek filled shape */}
      <path
        d={`M${xba} ${yba} L${xbb} ${ybb} L${xp} ${yp} Z`}
        fill="#e2e8f0"
        filter="drop-shadow(0 0 4px rgba(226,232,240,0.6))"
      />
    </g>
  );
};

/**
 * Main Component: PhishingRiskSpeedometer
 */
export default function PhishingRiskSpeedometer({
  riskScore,
  animationDuration = 800,
  className = '',
}: PhishingRiskSpeedometerProps) {
  const [displayScore, setDisplayScore] = useState(riskScore);
  const clampedScore = clamp(riskScore, 0, 100);
  const riskColor = getRiskColor(clampedScore);

  useEffect(() => {
    setDisplayScore(clampedScore);
  }, [clampedScore]);

  // Chart dimensions
  const chartWidth = 280;
  const chartHeight = 140; // Semi-circle only
  const centerX = chartWidth / 2;
  const centerY = chartHeight; // Bottom alignment for flat-bottom semi-circle

  return (
    <div className={`flex flex-col items-center justify-center w-full ${className}`}>
      {/* Recharts Gauge Chart */}
      <div className="w-full flex justify-center bg-transparent">
        <ResponsiveContainer width={chartWidth} height={chartHeight}>
          <PieChart
            data={RISK_ZONES}
            margin={{ top: 0, right: 0, bottom: 0, left: 0 }}
          >
            <Pie
              data={RISK_ZONES}
              cx="50%"
              cy="100%"
              startAngle={180}
              endAngle={0}
              innerRadius={60}
              outerRadius={90}
              dataKey="value"
              strokeWidth={0}
            >
              {RISK_ZONES.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Pie>

            {/* Custom Needle Shape */}
            <CustomNeedle
              cx={centerX}
              cy={centerY}
              outerRadius={90}
              riskScore={displayScore}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Readout Section */}
      <div className="mt-4 text-center">
        {/* Large percentage display */}
        <div
          className="text-5xl font-black font-mono text-white"
          style={{ color: riskColor.primary }}
        >
          {Math.round(displayScore)}%
        </div>

        {/* Risk level badge */}
        <div
          className="inline-block px-4 py-1.5 rounded-full text-xs font-bold text-white"
          style={{
            backgroundColor: riskColor.primary.replace(')', ', 0.15)').replace('rgb', 'rgba'),
            border: `1.5px solid ${riskColor.primary}`,
          }}
        >
          {riskColor.label}
        </div>
      </div>
    </div>
  );
}
