import React from 'react';

interface SecurityDNAProps {
  headerScore: number;
  linkScore: number;
  contentScore: number;
}

export default function SecurityDNA({ headerScore, linkScore, contentScore }: SecurityDNAProps) {
  const getColor = (score: number) => {
    if (score > 0.7) return { bg: 'bg-red-900/40', border: 'border-red-500/50', text: 'text-red-300', label: 'CRITICAL' };
    if (score > 0.45) return { bg: 'bg-yellow-900/40', border: 'border-yellow-500/50', text: 'text-yellow-300', label: 'WARNING' };
    if (score > 0.3) return { bg: 'bg-orange-900/40', border: 'border-orange-500/50', text: 'text-orange-300', label: 'MEDIUM' };
    return { bg: 'bg-green-900/40', border: 'border-green-500/50', text: 'text-green-300', label: 'SAFE' };
  };

  const analyses = [
    {
      icon: '📧',
      title: 'Header Analysis',
      score: headerScore,
      indicators: [
        'SPF/DKIM/DMARC validation',
        'Sender authenticity check',
        'Routing vulnerability scan'
      ]
    },
    {
      icon: '🔗',
      title: 'Link Analysis',
      score: linkScore,
      indicators: [
        'URL domain reputation',
        'Redirect detection',
        'SSL certificate validation'
      ]
    },
    {
      icon: '📄',
      title: 'Content Analysis',
      score: contentScore,
      indicators: [
        'Phishing intent detection',
        'Urgency language patterns',
        'Credential harvest indicators'
      ]
    }
  ];

  return (
    <div className="space-y-6">
      <h3 className="text-xl font-bold text-white flex items-center gap-2">
        <span className="text-2xl">🧬</span> Security DNA Analysis
      </h3>

      <div className="grid grid-cols-3 gap-4">
        {analyses.map((analysis, idx) => {
          const colorScheme = getColor(analysis.score);
          return (
            <div
              key={idx}
              className={`${colorScheme.bg} border-2 ${colorScheme.border} rounded-xl p-5 backdrop-blur-sm transition-all duration-300 hover:scale-105 hover:shadow-lg`}
              style={{
                boxShadow: `0 0 20px ${
                  analysis.score > 0.7 ? 'rgba(239,68,68,0.2)' :
                  analysis.score > 0.45 ? 'rgba(234,179,8,0.2)' :
                  analysis.score > 0.3 ? 'rgba(249,115,22,0.2)' :
                  'rgba(34,197,94,0.2)'
                }`
              }}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-3xl">{analysis.icon}</span>
                <div className="text-right">
                  <div className={`text-2xl font-bold ${colorScheme.text}`}>
                    {Math.round(analysis.score * 100)}%
                  </div>
                  <div className={`text-xs font-bold uppercase tracking-wide ${colorScheme.text}`}>
                    {colorScheme.label}
                  </div>
                </div>
              </div>

              <div className="w-full h-2 bg-slate-700/50 rounded-full overflow-hidden mb-4">
                <div
                  className={`h-full transition-all duration-300 rounded-full ${
                    analysis.score > 0.7 ? 'bg-gradient-to-r from-red-500 to-red-400' :
                    analysis.score > 0.45 ? 'bg-gradient-to-r from-yellow-500 to-yellow-400' :
                    analysis.score > 0.3 ? 'bg-gradient-to-r from-orange-500 to-orange-400' :
                    'bg-gradient-to-r from-green-500 to-green-400'
                  }`}
                  style={{ width: `${Math.min(analysis.score * 100, 100)}%` }}
                ></div>
              </div>

              <h4 className="text-sm font-bold text-white mb-2">{analysis.title}</h4>
              <ul className="text-xs space-y-1 text-slate-300">
                {analysis.indicators.map((indicator, i) => (
                  <li key={i} className="flex items-center gap-2">
                    <span className="w-1 h-1 bg-slate-400 rounded-full"></span>
                    {indicator}
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>
    </div>
  );
}
