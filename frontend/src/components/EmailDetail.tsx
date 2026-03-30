
import React from 'react';
import SpeedoMeter from './SpeedoMeter';
import ScoreComponents from './ScoreComponents';
import Quiz from './Quiz';

// Tech color map for highlights
const highlightColor: Record<string, string> = {
  High: 'bg-red-600 text-red-100',
  Medium: 'bg-orange-600 text-orange-100',
  Low: 'bg-emerald-600 text-emerald-100',
};

// Tech badge colors
const heuristicColor: Record<string, string> = {
  'Suspicious URL': 'bg-red-600/30 text-red-200 border border-red-500/60',
  'SPF failed': 'bg-red-600/30 text-red-200 border border-red-500/60',
  'DKIM failed': 'bg-red-600/30 text-red-200 border border-red-500/60',
  'DMARC failed': 'bg-red-600/30 text-red-200 border border-red-500/60',
};

// Highlight risky tokens in the email body
function highlightText(text: string, highlights: string[], risk: string) {
  if (!highlights || highlights.length === 0) return text;
  let result = text;
  highlights.forEach(token => {
    const re = new RegExp(`(${token})`, 'gi');
    result = result.replace(re, '<mark class="' + (highlightColor[risk] || 'bg-yellow-600') + ' px-1 rounded">$1</mark>');
  });
  return <span dangerouslySetInnerHTML={{ __html: result }} />;
}

// Heuristic badges with tooltips
function HeuristicBadges({ heuristics }: { heuristics: string[] }) {
  return (
    <div className="flex flex-wrap gap-2 mt-2">
      {heuristics.map((h, i) => (
        <span
          key={i}
          className={`px-2 py-1 rounded text-xs font-semibold cursor-help ${heuristicColor[h] || 'bg-gray-700 text-gray-300'}`}
          title={h}
        >
          {h}
        </span>
      ))}
    </div>
  );
}

// Main EmailDetail component - Complete UI Overhaul with SpeedoMeter
const EmailDetail: React.FC<{ email: any }> = ({ email }) => {
  const finalScore = email.final_score || 0;
  const isHighRisk = finalScore >= 0.65;

  return (
    <div className="w-full h-full bg-black overflow-y-auto p-6"
      style={{
        background: 'linear-gradient(135deg, #0a0e27 0%, #0f1419 50%, #0a0e27 100%)',
      }}>
      
      {/* Header */}
      <div className="mb-8 pb-6 border-b-2 border-cyan-600/40">
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1">
            <h2 className="text-3xl font-mono font-bold text-cyan-300 break-all mb-2" 
              style={{ textShadow: '0 0 15px rgba(34, 211, 238, 0.8)' }}>
              📧 {email.subject}
            </h2>
            <div className="text-sm text-cyan-400 font-mono space-y-1">
              <div><span className="text-lime-400">[FROM]</span> {email.sender}</div>
              <div><span className="text-lime-400">[TIME]</span> {email.timestamp || 'N/A'}</div>
            </div>
          </div>
          <div className="text-right">
            <span className={`px-4 py-2 border-2 font-mono text-sm font-bold ${
              isHighRisk 
                ? 'border-red-500 text-red-300 bg-red-600/10' 
                : 'border-emerald-500 text-emerald-300 bg-emerald-600/10'
            }`}
              style={{
                boxShadow: isHighRisk 
                  ? '0 0 15px rgba(239, 68, 68, 0.6)' 
                  : '0 0 15px rgba(16, 185, 129, 0.6)'
              }}>
              {isHighRisk ? '🔴 THREAT' : '🟢 SAFE'}
            </span>
          </div>
        </div>
      </div>

      {/* Main Grid: Speedometer + Score Details */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 mb-8">
        {/* Left: Speedometer */}
        <div className="flex justify-center items-start">
          <div className="w-full max-w-sm">
            <SpeedoMeter score={finalScore} label="OVERALL_RISK" />
          </div>
        </div>

        {/* Right: Score Components Breakdown */}
        <div className="overflow-y-auto" style={{ maxHeight: '600px' }}>
          <ScoreComponents email={email} />
        </div>
      </div>

      {/* Threat Analysis Section */}
      {email.reasons && email.reasons.length > 0 && (
        <div className="mb-8">
          <div className="text-sm font-mono text-red-400 mb-4 flex items-center gap-2">
            <span className="inline-block w-3 h-3 bg-red-500 animate-pulse rounded-full"></span>
            DETECTED_THREATS ({email.reasons.length})
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {email.reasons.slice(0, 8).map((reason: string, idx: number) => (
              <div
                key={idx}
                className="p-3 bg-red-600/10 border border-red-500/40 rounded-lg hover:bg-red-600/20 transition-all"
                style={{
                  boxShadow: 'inset 0 0 10px rgba(239, 68, 68, 0.05)',
                }}>
                <div className="text-xs font-mono text-red-300">
                  <span className="text-red-500 font-bold">[ALERT]</span> {reason}
                </div>
              </div>
            ))}
          </div>
          {email.reasons.length > 8 && (
            <div className="mt-3 text-xs font-mono text-slate-500">
              ... and {email.reasons.length - 8} more threats
            </div>
          )}
        </div>
      )}

      {/* AI Explanation */}
      {email.ai_analysis?.explanation || email.groq_analysis?.explanation ? (
        <div className="mb-8 p-4 border-2 border-lime-600/40 bg-lime-600/10 rounded-lg"
          style={{
            boxShadow: '0 0 20px rgba(132, 204, 22, 0.2), inset 0 0 10px rgba(132, 204, 22, 0.05)',
          }}>
          <div className="text-sm font-mono text-lime-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-lime-400 animate-pulse"></span>
            AI_EXPLANATION
          </div>
          <p className="text-sm text-lime-300 font-mono leading-relaxed">
            {email.ai_analysis?.explanation || email.groq_analysis?.explanation}
          </p>
        </div>
      ) : null}

      {/* Email Body */}
      {(email.email_text || email.body) && (
        <div className="mb-8">
          <div className="text-sm font-mono text-cyan-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-cyan-400 animate-pulse"></span>
            EMAIL_CONTENT
          </div>
          <div className="bg-black/60 p-4 border border-cyan-600/30 rounded-lg max-h-64 overflow-y-auto font-mono text-xs text-cyan-300"
            style={{
              boxShadow: 'inset 0 0 10px rgba(34, 211, 238, 0.05)',
            }}>
            {highlightText(email.email_text || email.body || '', email.highlighted_tokens || email.highlight?.phrases || [], email.risk_score || email.risk_level)}
          </div>
        </div>
      )}

      {/* Security Tip */}
      <div className="mb-8 p-4 border-l-4 border-blue-500 bg-blue-600/10 rounded-lg"
        style={{
          boxShadow: '0 0 15px rgba(59, 130, 246, 0.2)',
        }}>
        <div className="text-sm font-mono text-blue-400 mb-2 flex items-center gap-2">
          <span>🛡️</span> SECURITY_PROTOCOL
        </div>
        <p className="text-xs text-blue-300 font-mono">
          Always verify sender addresses. Never click suspicious links. Check email headers. Enable multi-factor authentication. Report phishing to IT.
        </p>
      </div>

      {/* Quiz Section */}
      {email.quiz && email.quiz.length > 0 && (
        <div className="p-4 border-2 border-purple-600/40 bg-purple-600/10 rounded-lg"
          style={{
            boxShadow: '0 0 15px rgba(168, 85, 247, 0.2)',
          }}>
          <div className="text-sm font-mono text-purple-400 mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-purple-400 animate-pulse"></span>
            INTERACTIVE_TRAINING
          </div>
          <Quiz quiz={email.quiz} />
        </div>
      )}
    </div>
  );
};

export default EmailDetail;
