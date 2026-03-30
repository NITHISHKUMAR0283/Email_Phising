import React, { useState } from 'react';

interface URLAnalysis {
  url: string;
  risk_score: number;
  risk_level: string;
  threat_type: string;
  findings: string[];
  is_suspicious: boolean;
  details: {
    domain?: any;
    structural?: any;
    brand?: any;
    certificate?: any;
    redirect?: any;
    threat_intel?: any;
    contextual?: any;
    verdict?: any;
  };
  raw_result?: any;
}

interface URLAnalysisDetailProps {
  urls?: URLAnalysis[];
  email_urls?: string[];
}

const URLAnalysisDetail: React.FC<URLAnalysisDetailProps> = ({ urls = [], email_urls = [] }) => {
  const [expandedPhase, setExpandedPhase] = useState<string | null>(null);

  if (!urls || urls.length === 0) {
    return null;
  }

  const getRiskColor = (score: number) => {
    if (score >= 0.8) return 'text-red-400 bg-red-600/10 border-red-500/40';
    if (score >= 0.6) return 'text-orange-400 bg-orange-600/10 border-orange-500/40';
    if (score >= 0.4) return 'text-yellow-400 bg-yellow-600/10 border-yellow-500/40';
    return 'text-emerald-400 bg-emerald-600/10 border-emerald-500/40';
  };

  const getRiskBadgeColor = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-600 text-red-100';
      case 'HIGH':
        return 'bg-orange-600 text-orange-100';
      case 'MEDIUM':
        return 'bg-yellow-600 text-yellow-100';
      case 'LOW':
        return 'bg-blue-600 text-blue-100';
      default:
        return 'bg-emerald-600 text-emerald-100';
    }
  };

  const togglePhase = (phase: string) => {
    setExpandedPhase(expandedPhase === phase ? null : phase);
  };

  const renderDetailValue = (value: any): React.ReactNode => {
    if (!value) return 'N/A';
    if (typeof value === 'boolean') return value ? '✓ Yes' : '✗ No';
    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        return value.length > 0 ? value.join(', ') : 'None';
      }
      return JSON.stringify(value, null, 2);
    }
    return String(value);
  };

  const PhaseCard = ({
    title,
    subtitle,
    icon,
    phase,
    details,
  }: {
    title: string;
    subtitle: string;
    icon: string;
    phase: string;
    details: any;
  }) => {
    const isExpanded = expandedPhase === phase;
    const hasData = details && Object.keys(details).length > 0;

    if (!hasData) return null;

    return (
      <div className="border border-slate-600/40 rounded-lg overflow-hidden">
        <button
          onClick={() => togglePhase(phase)}
          className="w-full px-4 py-3 bg-slate-800/50 hover:bg-slate-700/50 transition-all flex items-center justify-between"
        >
          <div className="flex items-center gap-3">
            <span className="text-2xl">{icon}</span>
            <div className="text-left">
              <div className="font-mono text-sm font-bold text-cyan-300">{title}</div>
              <div className="font-mono text-xs text-slate-400">{subtitle}</div>
            </div>
          </div>
          <span className={`transition-transform ${isExpanded ? 'rotate-180' : ''} text-slate-400`}>
            ▼
          </span>
        </button>

        {isExpanded && (
          <div className="p-4 bg-black/40 border-t border-slate-600/20 max-h-96 overflow-y-auto">
            {typeof details === 'object' && details !== null ? (
              <div className="space-y-2">
                {Object.entries(details).map(([key, value]) => (
                  <div key={key} className="font-mono text-xs">
                    <span className="text-slate-500">{key}:</span>
                    <span className="text-slate-300 ml-2">
                      {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-slate-400 text-xs font-mono">{String(details)}</div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {urls.map((url, idx) => (
        <div key={idx} className="space-y-4">
          {/* URL Header */}
          <div className="border-b border-slate-600/40 pb-4">
            <div className="flex items-start justify-between mb-3">
              <div className="flex-1">
                <div className="text-sm font-mono text-slate-400 mb-2">URL #{idx + 1}</div>
                <div className="font-mono text-sm text-cyan-300 break-all mb-3">{url.url}</div>
              </div>
              <span className={`px-3 py-1 rounded-full text-xs font-mono font-bold whitespace-nowrap ml-4 ${getRiskBadgeColor(url.risk_level)}`}>
                {url.risk_level}
              </span>
            </div>

            {/* Risk Score Gauge */}
            <div className="grid grid-cols-3 gap-3">
              <div className={`p-3 rounded border ${getRiskColor(url.risk_score)}`}>
                <div className="text-xs text-slate-400 font-mono">Risk Score</div>
                <div className="text-lg font-mono font-bold">{(url.risk_score * 100).toFixed(0)}%</div>
              </div>
              <div className="p-3 rounded border border-slate-600/40 bg-slate-700/20">
                <div className="text-xs text-slate-400 font-mono">Threat Type</div>
                <div className="text-xs font-mono text-slate-300 mt-1 truncate">{url.threat_type}</div>
              </div>
              <div className="p-3 rounded border border-slate-600/40 bg-slate-700/20">
                <div className="text-xs text-slate-400 font-mono">Findings</div>
                <div className="text-lg font-mono font-bold text-slate-300">{url.findings.length}</div>
              </div>
            </div>
          </div>

          {/* Key Findings */}
          {url.findings && url.findings.length > 0 && (
            <div>
              <div className="text-xs font-mono text-red-400 mb-2 font-bold">🚨 KEY FINDINGS</div>
              <div className="space-y-2">
                {url.findings.slice(0, 5).map((finding, fidx) => (
                  <div
                    key={fidx}
                    className="p-3 bg-red-600/10 border border-red-500/30 rounded text-xs font-mono text-red-300"
                  >
                    • {finding}
                  </div>
                ))}
                {url.findings.length > 5 && (
                  <div className="text-xs text-slate-500 font-mono">
                    ... and {url.findings.length - 5} more findings
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Analysis Phases */}
          {url.details && (
            <div className="space-y-2">
              <div className="text-xs font-mono text-cyan-400 font-bold mb-3">
                📊 DETAILED_ANALYSIS (13 Phases)
              </div>

              {/* Phase 1: Structural Analysis */}
              {url.details.structural && (
                <PhaseCard
                  title="Structural Analysis"
                  subtitle="Phase 1 — URL format & pathology"
                  icon="📐"
                  phase="structural"
                  details={url.details.structural}
                />
              )}

              {/* Phase 2: Domain Intelligence */}
              {url.details.domain && (
                <PhaseCard
                  title="Domain Intelligence"
                  subtitle="Phase 2 — Registrar & DNS checks"
                  icon="🌐"
                  phase="domain"
                  details={url.details.domain}
                />
              )}

              {/* Phase 3: Brand Detection */}
              {url.details.brand && (
                <PhaseCard
                  title="Brand Detection"
                  subtitle="Phase 3 — Impersonation & lookalikes"
                  icon="🎭"
                  phase="brand"
                  details={url.details.brand}
                />
              )}

              {/* Phase 4: Certificate Analysis */}
              {url.details.certificate && (
                <PhaseCard
                  title="SSL/Certificate Analysis"
                  subtitle="Phase 4 — HTTPS & encryption validation"
                  icon="🔒"
                  phase="certificate"
                  details={url.details.certificate}
                />
              )}

              {/* Phase 5: Redirect Analysis */}
              {url.details.redirect && (
                <PhaseCard
                  title="Redirect Chain Analysis"
                  subtitle="Phase 5 — URL shorteners & redirects"
                  icon="🔗"
                  phase="redirect"
                  details={url.details.redirect}
                />
              )}

              {/* Phase 6: Threat Intelligence */}
              {url.details.threat_intel && (
                <PhaseCard
                  title="Threat Intelligence"
                  subtitle="Phase 6 — VirusTotal & blacklist checks"
                  icon="⚠️"
                  phase="threat_intel"
                  details={url.details.threat_intel}
                />
              )}

              {/* Phase 7: Contextual Analysis */}
              {url.details.contextual && (
                <PhaseCard
                  title="Contextual Analysis"
                  subtitle="Phase 7 — Forms, content & intent"
                  icon="🔍"
                  phase="contextual"
                  details={url.details.contextual}
                />
              )}

              {/* Verdict */}
              {url.details.verdict && (
                <PhaseCard
                  title="Final Verdict"
                  subtitle="Analysis conclusion & recommendation"
                  icon="✅"
                  phase="verdict"
                  details={url.details.verdict}
                />
              )}
            </div>
          )}

          {/* Raw Data (Debug) */}
          {url.raw_result && (
            <details className="cursor-pointer">
              <summary className="text-xs font-mono text-slate-500 hover:text-slate-400">
                ▶ Raw Analysis Data (Debug)
              </summary>
              <div className="mt-2 p-3 bg-black/60 border border-slate-700 rounded font-mono text-xs text-slate-400 max-h-64 overflow-y-auto">
                <pre>{JSON.stringify(url.raw_result, null, 2)}</pre>
              </div>
            </details>
          )}
        </div>
      ))}

      {/* URLs Not Analyzed */}
      {email_urls && email_urls.length > urls.length && (
        <div className="p-3 bg-slate-800/40 border border-slate-600/40 rounded">
          <div className="text-xs font-mono text-slate-500">
            ℹ️ {email_urls.length - urls.length} additional URL(s) found but not yet analyzed
          </div>
        </div>
      )}
    </div>
  );
};

export default URLAnalysisDetail;
