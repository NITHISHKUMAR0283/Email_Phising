import React from 'react';
import RiskBadge from './RiskBadge';

interface ScoreBreakdownProps {
  email: {
    final_score?: number;
    risk_level?: string;
    components?: {
      url_score?: number;
      domain_score?: number;
      intent_score?: number;
      text_score?: number;
    };
    confidence?: number;
    signal_agreement?: number;
    is_whitelisted?: boolean;
  };
}

export default function ScoreBreakdown({ email }: ScoreBreakdownProps) {
  const finalScore = (email.final_score || 0) * 100;
  const components = email.components || {};

  const scores = [
    { label: 'URL Score', value: components.url_score, icon: '🔗', color: 'text-red-600' },
    { label: 'Domain Score', value: components.domain_score, icon: '🌐', color: 'text-orange-600' },
    { label: 'Intent Score', value: components.intent_score, icon: '⚡', color: 'text-yellow-600' },
    { label: 'Text Score', value: components.text_score, icon: '📝', color: 'text-purple-600' },
  ];

  return (
    <div className="w-full bg-gradient-to-br from-slate-900 to-slate-800 rounded-lg p-6 border border-slate-700">
      <h3 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
        <span>📊</span> Score Breakdown
      </h3>

      {/* Main Score Card */}
      <div className="mb-6 p-4 bg-black/40 rounded-lg border border-slate-600">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm mb-1">Final Risk Score</p>
            <p className="text-4xl font-bold text-white">{finalScore.toFixed(1)}%</p>
          </div>
          <div>
            <RiskBadge risk={email.risk_level || 'UNKNOWN'} />
          </div>
        </div>
      </div>

      {/* Component Scores Grid */}
      <div className="grid grid-cols-2 gap-3 mb-6">
        {scores.map((score) => (
          <div key={score.label} className="p-3 bg-black/40 rounded-lg border border-slate-600">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-lg">{score.icon}</span>
              <p className="text-xs text-slate-400">{score.label}</p>
            </div>
            <p className={`text-2xl font-bold ${score.color}`}>
              {score.value !== undefined ? (score.value * 100).toFixed(0) : 'N/A'}%
            </p>
          </div>
        ))}
      </div>

      {/* Metadata */}
      {email.confidence !== undefined && (
        <div className="p-3 bg-blue-600/10 rounded-lg border border-blue-600/30">
          <div className="flex justify-between items-center">
            <span className="text-sm text-slate-300">Confidence:</span>
            <span className="font-semibold text-blue-400">{(email.confidence * 100).toFixed(0)}%</span>
          </div>
          {email.signal_agreement !== undefined && (
            <div className="flex justify-between items-center mt-2 text-xs">
              <span className="text-slate-400">Signal Agreement:</span>
              <span className="text-slate-300">{email.signal_agreement} signals</span>
            </div>
          )}
        </div>
      )}

      {email.is_whitelisted && (
        <div className="mt-3 p-2 bg-green-600/10 rounded border border-green-600/30 text-xs text-green-400">
          ✓ Sender verified as known trusted domain
        </div>
      )}
    </div>
  );
}
