import React from 'react';

interface AnalysisReportProps {
  email: any;
}

const AnalysisReport: React.FC<AnalysisReportProps> = ({ email }) => {
  if (!email) return null;

  const riskColor = (score: number | undefined) => {
    if (!score) return 'text-gray-600';
    if (score >= 0.8) return 'text-red-600';
    if (score >= 0.65) return 'text-orange-600';
    if (score >= 0.45) return 'text-yellow-600';
    return 'text-green-600';
  };

  const riskBgColor = (score: number | undefined) => {
    if (!score) return 'bg-gray-100';
    if (score >= 0.8) return 'bg-red-100 border-red-300';
    if (score >= 0.65) return 'bg-orange-100 border-orange-300';
    if (score >= 0.45) return 'bg-yellow-100 border-yellow-300';
    return 'bg-green-100 border-green-300';
  };

  const ProgressBar = ({ score, label }: { score: number | undefined; label: string }) => {
    const percentage = Math.round((score || 0) * 100);
    return (
      <div className="mb-4">
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm font-semibold text-gray-700">{label}</span>
          <span className={`text-lg font-bold ${riskColor(score)}`}>{percentage}%</span>
        </div>
        <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${
              percentage >= 80
                ? 'bg-gradient-to-r from-red-400 to-red-600'
                : percentage >= 65
                ? 'bg-gradient-to-r from-orange-400 to-orange-600'
                : percentage >= 45
                ? 'bg-gradient-to-r from-yellow-400 to-yellow-600'
                : 'bg-gradient-to-r from-green-400 to-green-600'
            }`}
            style={{ width: `${percentage}%` }}
          ></div>
        </div>
      </div>
    );
  };

  return (
    <div className="w-full bg-gradient-to-b from-slate-900 to-slate-800 text-white rounded-xl shadow-2xl p-8">
      {/* Header */}
      <div className="mb-8 pb-6 border-b border-slate-700">
        <h1 className="text-3xl font-bold mb-2">📋 Email Analysis Report</h1>
        <p className="text-slate-400 text-sm">Comprehensive phishing detection assessment with all scoring metrics</p>
      </div>

      {/* Executive Summary */}
      <div className="mb-8 grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className={`p-6 rounded-lg border-2 ${riskBgColor(email.final_score)}`}>
          <div className="text-slate-700 text-sm font-semibold mb-2">FINAL VERDICT</div>
          <div className={`text-4xl font-bold ${riskColor(email.final_score)}`}>
            {((email.final_score || 0) * 100).toFixed(1)}%
          </div>
          <div className={`text-sm mt-2 ${email.risk_level === 'CRITICAL' || email.risk_level === 'HIGH' ? 'text-red-700' : 'text-gray-700'}`}>
            Risk Level: <span className="font-bold">{email.risk_level || 'UNKNOWN'}</span>
          </div>
          {email.confidence !== undefined && (
            <div className="text-xs text-gray-600 mt-2">Confidence: {((email.confidence || 0) * 100).toFixed(0)}%</div>
          )}
        </div>

        <div className="p-6 rounded-lg bg-slate-700 border-2 border-slate-600">
          <div className="text-slate-400 text-sm font-semibold mb-2">EMAIL METADATA</div>
          <div className="space-y-2 text-xs">
            <div><span className="text-slate-400">From:</span> <span className="text-white truncate">{email.sender || 'N/A'}</span></div>
            <div><span className="text-slate-400">Subject:</span> <span className="text-white truncate">{email.subject || 'N/A'}</span></div>
            <div><span className="text-slate-400">Timestamp:</span> <span className="text-white">{email.timestamp || 'N/A'}</span></div>
          </div>
        </div>

        <div className="p-6 rounded-lg bg-slate-700 border-2 border-slate-600">
          <div className="text-slate-400 text-sm font-semibold mb-2">ANALYSIS TIME</div>
          <div className="space-y-2 text-xs">
            <div><span className="text-slate-400">Total:</span> <span className="text-white">{((email.fetch_time_ms || 0) + (email.model_time_ms || 0) + (email.groq_time_ms || 0)).toFixed(0)}ms</span></div>
            <div><span className="text-slate-400">Models:</span> <span className="text-white">{(email.model_time_ms || 0).toFixed(0)}ms</span></div>
            <div><span className="text-slate-400">AI:</span> <span className="text-white">{(email.groq_time_ms || 0).toFixed(0)}ms</span></div>
          </div>
        </div>
      </div>

      {/* Primary Signals */}
      <div className="mb-8 p-6 rounded-lg bg-slate-700/50 border border-slate-600">
        <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
          <span>🎯</span> Primary Detection Signals
        </h2>

        <ProgressBar score={email.nlp_score} label="🧠 NLP/AI Analysis (Grok LLM)" />
        <div className="text-xs text-slate-400 mb-4">Semantic threat analysis - understanding the email's intent and content</div>

        <ProgressBar score={email.link_score} label="🔗 Link/URL Analysis (ML Models)" />
        <div className="text-xs text-slate-400 mb-4">URL patterns, domain reputation, and phishing indicators</div>

        <ProgressBar score={email.header_score} label="📧 Email Header/Authentication" />
        <div className="text-xs text-slate-400 mb-4">SPF, DKIM, DMARC verification, spoofing detection</div>

        {email.visual_score !== undefined && email.visual_score > 0 && (
          <>
            <ProgressBar score={email.visual_score} label="👁️ Visual/Logo Analysis" />
            <div className="text-xs text-slate-400 mb-4">Brand impersonation and visual spoofing detection</div>
          </>
        )}
      </div>

      {/* ML Model Breakdown */}
      {email.components && (
        <div className="mb-8">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <span>🔧</span> ML Model Breakdown
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {email.components.url_score !== undefined && (
              <div className="p-5 rounded-lg bg-red-500/20 border border-red-500/50 hover:border-red-500 transition">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-bold text-red-300">URL Model</span>
                  <span className="text-2xl font-bold text-red-400">{((email.components.url_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-slate-300">Detects suspicious URL patterns and credential harvesting</p>
                <div className="mt-3 h-2 bg-red-900/30 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500" style={{ width: `${(email.components.url_score || 0) * 100}%` }}></div>
                </div>
              </div>
            )}

            {email.components.domain_score !== undefined && (
              <div className="p-5 rounded-lg bg-blue-500/20 border border-blue-500/50 hover:border-blue-500 transition">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-bold text-blue-300">Domain Model</span>
                  <span className="text-2xl font-bold text-blue-400">{((email.components.domain_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-slate-300">Detects domain spoofing and impersonation attempts</p>
                <div className="mt-3 h-2 bg-blue-900/30 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500" style={{ width: `${(email.components.domain_score || 0) * 100}%` }}></div>
                </div>
              </div>
            )}

            {email.components.intent_score !== undefined && (
              <div className="p-5 rounded-lg bg-yellow-500/20 border border-yellow-500/50 hover:border-yellow-500 transition">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-bold text-yellow-300">Intent Model</span>
                  <span className="text-2xl font-bold text-yellow-400">{((email.components.intent_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-slate-300">Identifies urgency, action requests, and fear tactics</p>
                <div className="mt-3 h-2 bg-yellow-900/30 rounded-full overflow-hidden">
                  <div className="h-full bg-yellow-500" style={{ width: `${(email.components.intent_score || 0) * 100}%` }}></div>
                </div>
              </div>
            )}

            {email.components.text_score !== undefined && (
              <div className="p-5 rounded-lg bg-purple-500/20 border border-purple-500/50 hover:border-purple-500 transition">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-bold text-purple-300">Text Model</span>
                  <span className="text-2xl font-bold text-purple-400">{((email.components.text_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-slate-300">Analyzes overall email content for phishing indicators</p>
                <div className="mt-3 h-2 bg-purple-900/30 rounded-full overflow-hidden">
                  <div className="h-full bg-purple-500" style={{ width: `${(email.components.text_score || 0) * 100}%` }}></div>
                </div>
              </div>
            )}

            {email.components.vt_score !== null && email.components.vt_score !== undefined && (
              <div className="p-5 rounded-lg bg-green-500/20 border border-green-500/50 hover:border-green-500 transition">
                <div className="flex justify-between items-center mb-3">
                  <span className="font-bold text-green-300">VirusTotal</span>
                  <span className="text-2xl font-bold text-green-400">{((email.components.vt_score || 0) * 100).toFixed(0)}%</span>
                </div>
                <p className="text-xs text-slate-300">Verdict from 70+ antivirus engines</p>
                <div className="mt-3 h-2 bg-green-900/30 rounded-full overflow-hidden">
                  <div className="h-full bg-green-500" style={{ width: `${(email.components.vt_score || 0) * 100}%` }}></div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Email Authentication Details */}
      {email.header_analysis && (
        <div className="mb-8 p-6 rounded-lg bg-slate-700/50 border border-slate-600">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-2">
            <span>📧</span> Email Authentication (SPF/DKIM/DMARC)
          </h2>

          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className={`p-4 rounded-lg text-center border-2 ${
              email.header_analysis.spf?.toLowerCase() === 'pass'
                ? 'bg-green-500/20 border-green-500'
                : 'bg-red-500/20 border-red-500'
            }`}>
              <div className="text-lg font-bold mb-2">SPF</div>
              <div className={`text-2xl font-bold ${
                email.header_analysis.spf?.toLowerCase() === 'pass' ? 'text-green-400' : 'text-red-400'
              }`}>
                {email.header_analysis.spf?.toUpperCase() || 'NONE'}
              </div>
            </div>

            <div className={`p-4 rounded-lg text-center border-2 ${
              email.header_analysis.dkim?.toLowerCase() === 'pass'
                ? 'bg-green-500/20 border-green-500'
                : 'bg-red-500/20 border-red-500'
            }`}>
              <div className="text-lg font-bold mb-2">DKIM</div>
              <div className={`text-2xl font-bold ${
                email.header_analysis.dkim?.toLowerCase() === 'pass' ? 'text-green-400' : 'text-red-400'
              }`}>
                {email.header_analysis.dkim?.toUpperCase() || 'NONE'}
              </div>
            </div>

            <div className={`p-4 rounded-lg text-center border-2 ${
              email.header_analysis.dmarc?.toLowerCase() === 'pass'
                ? 'bg-green-500/20 border-green-500'
                : 'bg-red-500/20 border-red-500'
            }`}>
              <div className="text-lg font-bold mb-2">DMARC</div>
              <div className={`text-2xl font-bold ${
                email.header_analysis.dmarc?.toLowerCase() === 'pass' ? 'text-green-400' : 'text-red-400'
              }`}>
                {email.header_analysis.dmarc?.toUpperCase() || 'NONE'}
              </div>
            </div>
          </div>

          {email.header_analysis.is_spoofed && (
            <div className="p-4 rounded-lg bg-red-500/20 border border-red-500">
              <div className="font-bold text-red-300 mb-2">⚠️ Spoofing Detected</div>
              {email.header_analysis.spoofing_reasons && (
                <ul className="space-y-1 text-sm text-red-200">
                  {email.header_analysis.spoofing_reasons.map((reason: string, idx: number) => (
                    <li key={idx}>• {reason}</li>
                  ))}
                </ul>
              )}
            </div>
          )}

          <div className="mt-6 grid grid-cols-2 gap-4 text-sm">
            {email.header_analysis.hops && (
              <div className="p-3 bg-slate-600/50 rounded">
                <div className="text-slate-400">Routing Hops</div>
                <div className="text-lg font-bold text-slate-200">{email.header_analysis.hops}</div>
              </div>
            )}
            {email.header_analysis.originating_ip && (
              <div className="p-3 bg-slate-600/50 rounded">
                <div className="text-slate-400">Origin IP</div>
                <div className="text-lg font-bold text-slate-200 font-mono">{email.header_analysis.originating_ip}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Detection Reasons */}
      {email.reasons && email.reasons.length > 0 && (
        <div className="mb-8 p-6 rounded-lg bg-slate-700/50 border border-slate-600">
          <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
            <span>🚨</span> Detection Reasons ({email.reasons.length})
          </h2>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {email.reasons.map((reason: string, idx: number) => (
              <div key={idx} className="flex gap-3 p-3 bg-red-500/10 rounded border-l-4 border-red-500">
                <span className="text-red-400 font-bold text-lg flex-shrink-0">•</span>
                <span className="text-slate-300 text-sm">{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="border-t border-slate-700 pt-4 text-center text-xs text-slate-500">
        <p>PhishGuard AI - Powered by Multi-Signal Detection | {new Date().toLocaleString()}</p>
      </div>
    </div>
  );
};

export default AnalysisReport;
