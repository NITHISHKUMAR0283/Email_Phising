import React from 'react';

interface ComponentScores {
  url_score?: number;
  domain_score?: number;
  intent_score?: number;
  text_score?: number;
  header_score?: number;
  vt_score?: number | null;
}

interface ScoreBreakdownProps {
  components?: ComponentScores;
  final_score: number;
}

const ScoreBreakdown: React.FC<ScoreBreakdownProps> = ({ components, final_score }) => {
  if (!components) {
    return null;
  }

  // Determine color based on final score
  const getScoreColor = () => {
    if (final_score >= 0.65) return '#dc2626'; // Red for HIGH
    if (final_score >= 0.45) return '#ea580c'; // Amber for MEDIUM
    return '#06b6d4'; // Cyan for LOW
  };

  const getScoreColorClass = () => {
    if (final_score >= 0.65) return 'text-red-500';
    if (final_score >= 0.45) return 'text-amber-500';
    return 'text-emerald-400';
  };

  const getRiskLevel = () => {
    if (final_score >= 0.65) return 'CRITICAL';
    if (final_score >= 0.45) return 'MEDIUM';
    return 'SAFE';
  };

  const getMicroBarColor = () => {
    if (final_score >= 0.65) return 'bg-red-500/70';
    if (final_score >= 0.45) return 'bg-amber-500/70';
    return 'bg-emerald-500/50';
  };

  const getStatusColor = () => {
    if (final_score >= 0.65) return 'text-red-400 drop-shadow-[0_0_5px_rgba(220,38,38,0.8)]';
    if (final_score >= 0.45) return 'text-amber-400 drop-shadow-[0_0_5px_rgba(234,88,12,0.8)]';
    return 'text-emerald-400 drop-shadow-[0_0_5px_rgba(52,211,153,0.8)]';
  };

  return (
    <div className="bg-black/40 border border-zinc-800/50 rounded p-3 mt-4 flex flex-col gap-3">
      {/* Two-Column Layout: Left Risk Score + Right Micro-Telemetry Grid */}
      <div className="flex gap-4 w-full items-start">
        
        {/* Left Column: Global Risk Score */}
        <div className="flex flex-col justify-start min-w-fit">
          <p className="text-[7px] font-mono text-zinc-600 tracking-widest mb-2">▌ RISK_LVL</p>
          <p className={`text-4xl font-mono leading-tight font-bold ${getScoreColorClass()}`} style={{fontFamily: 'monospace', letterSpacing: '-0.05em', textShadow: `0 0 10px ${final_score >= 0.65 ? '#dc262680' : final_score >= 0.45 ? '#ea580c80' : '#06b6d480'}`}}>
            {(final_score * 100).toFixed(0)}%
          </p>
        </div>

        {/* Right Column: Micro-Telemetry Grid (2x2) */}
        <div className="grid grid-cols-2 gap-x-4 gap-y-2.5 flex-1">
          
          {/* URL */}
          <div className="flex flex-col">
            <div className="flex justify-between items-center mb-1.5 gap-2">
              <span className="font-mono text-[8px] text-zinc-400 tracking-wide">URL</span>
              <span className="font-mono text-[9px] text-zinc-200 font-semibold">{((components.url_score || 0) * 100).toFixed(0)}</span>
            </div>
            <div className="h-[2px] w-full bg-zinc-700/60 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${getMicroBarColor()}`}
                style={{ width: `${(components.url_score || 0) * 100}%` }}
              />
            </div>
          </div>

          {/* DOM */}
          <div className="flex flex-col">
            <div className="flex justify-between items-center mb-1.5 gap-2">
              <span className="font-mono text-[8px] text-zinc-400 tracking-wide">DOM</span>
              <span className="font-mono text-[9px] text-zinc-200 font-semibold">{((components.domain_score || 0) * 100).toFixed(0)}</span>
            </div>
            <div className="h-[2px] w-full bg-zinc-700/60 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${getMicroBarColor()}`}
                style={{ width: `${(components.domain_score || 0) * 100}%` }}
              />
            </div>
          </div>

          {/* INT */}
          <div className="flex flex-col">
            <div className="flex justify-between items-center mb-1.5 gap-2">
              <span className="font-mono text-[8px] text-zinc-400 tracking-wide">INT</span>
              <span className="font-mono text-[9px] text-zinc-200 font-semibold">{((components.intent_score || 0) * 100).toFixed(0)}</span>
            </div>
            <div className="h-[2px] w-full bg-zinc-700/60 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${getMicroBarColor()}`}
                style={{ width: `${(components.intent_score || 0) * 100}%` }}
              />
            </div>
          </div>

          {/* TXT */}
          <div className="flex flex-col">
            <div className="flex justify-between items-center mb-1.5 gap-2">
              <span className="font-mono text-[8px] text-zinc-400 tracking-wide">TXT</span>
              <span className="font-mono text-[9px] text-zinc-200 font-semibold">{((components.text_score || 0) * 100).toFixed(0)}</span>
            </div>
            <div className="h-[2px] w-full bg-zinc-700/60 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${getMicroBarColor()}`}
                style={{ width: `${(components.text_score || 0) * 100}%` }}
              />
            </div>
          </div>

        </div>
      </div>

      {/* Terminal Footer - Single Line Status Ticker */}
      <div className="bg-[#050505] border-t border-zinc-700/50 p-2 mt-2">
        <p className="font-mono text-[8px] text-zinc-400 truncate leading-relaxed">
          <span>&gt;</span>
          <span> SYS_CHK: OK | URL:</span>
          <span className="text-zinc-300">{((components.url_score || 0) * 100).toFixed(0)}</span>
          <span> DOM:</span>
          <span className="text-zinc-300">{((components.domain_score || 0) * 100).toFixed(0)}</span>
          <span> INT:</span>
          <span className="text-zinc-300">{((components.intent_score || 0) * 100).toFixed(0)}</span>
          <span> TXT:</span>
          <span className="text-zinc-300">{((components.text_score || 0) * 100).toFixed(0)}</span>
          <span> | STATUS: </span>
          <span className={getStatusColor()}>{getRiskLevel()}</span>
        </p>
      </div>
    </div>
  );
};


export default ScoreBreakdown;
