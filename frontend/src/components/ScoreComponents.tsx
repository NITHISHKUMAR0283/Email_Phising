import React from 'react';

interface ScoreComponentsProps {
  email: any;
}

const ScoreComponents: React.FC<ScoreComponentsProps> = ({ email }) => {
  const components = email.components || {};
  const nlpScore = email.nlp_score || components.nlp_score || 0;
  const linkScore = email.link_score || components.link_score || 0;
  const headerScore = email.header_score || components.header_score || 0;

  // Get individual model scores
  const urlScore = components.url_score || 0;
  const domainScore = components.domain_score || 0;
  const intentScore = components.intent_score || 0;
  const textScore = components.text_score || 0;
  const virusTotalScore = components.virus_total_score || 0;

  const scores = [
    { label: 'URL Detection', score: urlScore, icon: '🔗', category: 'ML Model' },
    { label: 'Domain Analysis', score: domainScore, icon: '🌐', category: 'ML Model' },
    { label: 'Intent Detection', score: intentScore, icon: '🎯', category: 'ML Model' },
    { label: 'Text Analysis', score: textScore, icon: '📝', category: 'ML Model' },
    { label: 'VirusTotal Check', score: virusTotalScore, icon: '⚠️', category: 'External API' },
    { label: 'NLP/Semantic', score: nlpScore, icon: '🧠', category: 'Primary Signal' },
    { label: 'Link Analysis', score: linkScore, icon: '🔍', category: 'Primary Signal' },
    { label: 'Email Headers', score: headerScore, icon: '📧', category: 'Primary Signal' },
  ];

  const getScoreColor = (score: number) => {
    if (score >= 0.8) return { bg: 'bg-red-600/20', border: 'border-red-500', text: 'text-red-300' };
    if (score >= 0.6) return { bg: 'bg-orange-600/20', border: 'border-orange-500', text: 'text-orange-300' };
    if (score >= 0.4) return { bg: 'bg-yellow-600/20', border: 'border-yellow-500', text: 'text-yellow-300' };
    return { bg: 'bg-emerald-600/20', border: 'border-emerald-500', text: 'text-emerald-300' };
  };

  const models = scores.filter(s => s.category === 'ML Model').filter(s => s.score > 0);
  const primary = scores.filter(s => s.category === 'Primary Signal').filter(s => s.score > 0);
  const external = scores.filter(s => s.category === 'External API').filter(s => s.score > 0);

  return (
    <div className="w-full space-y-6">
      {/* Primary Signals */}
      {primary.length > 0 && (
        <div>
          <div className="text-sm font-mono text-cyan-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-cyan-400 animate-pulse"></span>
            PRIMARY_SIGNALS (Weighted Scores)
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {primary.map((item) => {
              const colors = getScoreColor(item.score);
              const percentage = (item.score * 100).toFixed(0);
              return (
                <div
                  key={item.label}
                  className={`p-4 rounded-lg border-2 ${colors.border} ${colors.bg} backdrop-blur-sm transition-all hover:shadow-lg`}
                  style={{
                    boxShadow: `0 0 15px ${colors.border.replace('border-', 'rgba(').replace('500', '400, 0.3)')}`,
                  }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-2xl">{item.icon}</div>
                    <div className={`text-lg font-bold font-mono ${colors.text}`}>
                      {percentage}%
                    </div>
                  </div>
                  <div className="text-sm text-slate-300 font-mono">{item.label}</div>
                  <div className="h-1.5 bg-black/50 rounded-full mt-2 overflow-hidden border border-slate-700">
                    <div
                      className={`h-full transition-all ${colors.bg.replace('/20', '')}`}
                      style={{ width: `${item.score * 100}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ML Models */}
      {models.length > 0 && (
        <div>
          <div className="text-sm font-mono text-lime-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-lime-400 animate-pulse"></span>
            ML_MODELS (Individual Detectors)
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {models.map((item) => {
              const colors = getScoreColor(item.score);
              const percentage = (item.score * 100).toFixed(0);
              return (
                <div
                  key={item.label}
                  className={`p-3 rounded border ${colors.border} ${colors.bg}`}
                  style={{
                    boxShadow: `inset 0 0 10px ${colors.border.replace('border-', 'rgba(').replace('500', '400, 0.1)')}`,
                  }}
                >
                  <div className="text-xs font-mono text-slate-400 mb-1">{item.icon} {item.label}</div>
                  <div className={`text-2xl font-bold font-mono ${colors.text}`}>{percentage}%</div>
                  <div className="h-1 bg-black/30 rounded mt-2 overflow-hidden">
                    <div
                      className={`h-full transition-all ${colors.bg.replace('/20', '')}`}
                      style={{ width: `${item.score * 100}%` }}
                    ></div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* External Services */}
      {external.length > 0 && (
        <div>
          <div className="text-sm font-mono text-blue-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-blue-400 animate-pulse"></span>
            EXTERNAL_SERVICES
          </div>
          <div className="grid grid-cols-1 gap-2">
            {external.map((item) => {
              const colors = getScoreColor(item.score);
              const percentage = (item.score * 100).toFixed(0);
              return (
                <div
                  key={item.label}
                  className={`p-3 rounded border-l-4 ${colors.border} ${colors.bg} flex items-center justify-between`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{item.icon}</span>
                    <span className="text-sm font-mono text-slate-300">{item.label}</span>
                  </div>
                  <div className={`text-lg font-bold font-mono ${colors.text}`}>{percentage}%</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default ScoreComponents;
