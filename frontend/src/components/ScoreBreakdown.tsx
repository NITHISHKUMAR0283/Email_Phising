import React from 'react';

interface ScoreData {
  final_score?: number;
  risk_level?: string;
  confidence?: number;
  nlp_score?: number;
  link_score?: number;
  header_score?: number;
  visual_score?: number;
  components?: {
    url_score?: number;
    domain_score?: number;
    intent_score?: number;
    text_score?: number;
    header_score?: number;
    vt_score?: number | null;
  };
  header_analysis?: {
    spf?: string;
    dkim?: string;
    dmarc?: string;
    is_spoofed?: boolean;
    spoofing_reasons?: string[];
    hops?: number;
    originating_ip?: string | null;
  };
}

const ScoreBreakdown: React.FC<{ email: any }> = ({ email }) => {
  // Score severity colors
  const getSeverityColor = (score: number | undefined) => {
    if (score === undefined || score === null) return 'bg-gray-100 text-gray-700';
    if (score >= 0.8) return 'bg-red-100 text-red-800';
    if (score >= 0.6) return 'bg-orange-100 text-orange-800';
    if (score >= 0.4) return 'bg-yellow-100 text-yellow-800';
    return 'bg-green-100 text-green-700';
  };

  const getRiskLevelColor = (level: string | undefined) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-600 text-white';
      case 'MEDIUM':
        return 'bg-yellow-600 text-white';
      case 'LOW':
        return 'bg-blue-600 text-white';
      case 'SAFE':
        return 'bg-green-600 text-white';
      default:
        return 'bg-gray-600 text-white';
    }
  };

  const ScoreItem = ({ label, score, description }: { label: string; score: number | undefined; description?: string }) => (
    <div className="mb-3 p-3 bg-gray-50 rounded border border-gray-200">
      <div className="flex justify-between items-center">
        <span className="font-semibold text-sm">{label}</span>
        {score !== undefined && score !== null ? (
          <span className={`px-3 py-1 rounded font-bold text-sm ${getSeverityColor(score)}`}>
            {(score * 100).toFixed(1)}%
          </span>
        ) : (
          <span className="px-3 py-1 rounded text-gray-400 text-sm">N/A</span>
        )}
      </div>
      {description && <p className="text-xs text-gray-600 mt-1">{description}</p>}
    </div>
  );

  return (
    <div className="w-full bg-gradient-to-br from-blue-50 to-indigo-50 rounded-lg shadow p-6 mb-4 border border-indigo-200">
      {/* Main Risk Level */}
      <div className="mb-6 text-center">
        <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Risk Assessment</h3>
        <div className={`inline-block px-6 py-3 rounded-lg font-bold text-xl ${getRiskLevelColor(email.risk_level)}`}>
          {email.risk_level || 'UNKNOWN'}
        </div>
        <div className="mt-2 text-sm text-gray-600">
          Final Score: <span className="font-bold text-lg">{((email.final_score || 0) * 100).toFixed(1)}%</span>
        </div>
        {email.confidence !== undefined && (
          <div className="mt-1 text-xs text-gray-500">
            Confidence: {((email.confidence || 0) * 100).toFixed(0)}%
          </div>
        )}
      </div>

      {/* Primary Signals (for judges) */}
      <div className="mb-6">
        <h4 className="text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Primary Detection Signals</h4>
        
        {/* NLP Score (Grok AI) */}
        <ScoreItem 
          label="🧠 NLP / AI Analysis (Grok)"
          score={email.nlp_score}
          description="Semantic threat analysis via LLM"
        />

        {/* Link Score (ML Models) */}
        <ScoreItem 
          label="🔗 Link / URL Analysis (ML)"
          score={email.link_score}
          description="URL, domain, and phishing pattern detection"
        />

        {/* Header Score (Authentication) */}
        <ScoreItem 
          label="📧 Email Header / Authentication"
          score={email.header_score}
          description="SPF, DKIM, DMARC, spoofing detection"
        />

        {/* Visual Score (placeholder) */}
        {email.visual_score !== undefined && email.visual_score > 0 && (
          <ScoreItem 
            label="👁️ Visual / Logo Analysis"
            score={email.visual_score}
            description="Brand impersonation & visual spoofing"
          />
        )}
      </div>

      {/* Detailed ML Components (breakdown of Link score) */}
      {email.components && (
        <div className="mb-6 p-3 bg-white rounded border border-gray-300">
          <h4 className="text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">ML Model Breakdown</h4>
          
          <ScoreItem 
            label="URL Model"
            score={email.components.url_score}
            description="Detects suspicious URLs"
          />

          <ScoreItem 
            label="Domain Model"
            score={email.components.domain_score}
            description="Domain spoofing detection"
          />

          <ScoreItem 
            label="Intent Model"
            score={email.components.intent_score}
            description="Phishing intent & urgency"
          />

          <ScoreItem 
            label="Text Model"
            score={email.components.text_score}
            description="Email body content analysis"
          />

          {email.components.vt_score !== null && email.components.vt_score !== undefined && (
            <ScoreItem 
              label="VirusTotal"
              score={email.components.vt_score}
              description="70+ AV engines verdict"
            />
          )}
        </div>
      )}

      {/* Email Header Authentication Details */}
      {email.header_analysis && (
        <div className="mb-6 p-3 bg-white rounded border border-gray-300">
          <h4 className="text-sm font-bold text-gray-700 mb-3 uppercase tracking-wide">Email Authentication</h4>
          
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold">SPF</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                email.header_analysis.spf?.toLowerCase() === 'pass' 
                  ? 'bg-green-200 text-green-800' 
                  : 'bg-red-200 text-red-800'
              }`}>
                {email.header_analysis.spf?.toUpperCase() || 'NONE'}
              </span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold">DKIM</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                email.header_analysis.dkim?.toLowerCase() === 'pass' 
                  ? 'bg-green-200 text-green-800' 
                  : 'bg-red-200 text-red-800'
              }`}>
                {email.header_analysis.dkim?.toUpperCase() || 'NONE'}
              </span>
            </div>
            
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold">DMARC</span>
              <span className={`px-2 py-1 rounded text-xs font-bold ${
                email.header_analysis.dmarc?.toLowerCase() === 'pass' 
                  ? 'bg-green-200 text-green-800' 
                  : 'bg-red-200 text-red-800'
              }`}>
                {email.header_analysis.dmarc?.toUpperCase() || 'NONE'}
              </span>
            </div>

            {email.header_analysis.is_spoofed && (
              <div className="mt-3 p-2 bg-red-100 rounded border border-red-300">
                <p className="text-xs font-bold text-red-800">⚠️ Spoofing Detected</p>
                {email.header_analysis.spoofing_reasons && email.header_analysis.spoofing_reasons.length > 0 && (
                  <ul className="text-xs text-red-700 mt-1 ml-3">
                    {email.header_analysis.spoofing_reasons.map((reason: string, idx: number) => (
                      <li key={idx}>• {reason}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {email.header_analysis.hops && (
              <div className="text-xs text-gray-600 mt-2">
                Routing hops: {email.header_analysis.hops}
              </div>
            )}

            {email.header_analysis.originating_ip && (
              <div className="text-xs text-gray-600">
                Originating IP: {email.header_analysis.originating_ip}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Detection Reasons */}
      {email.reasons && email.reasons.length > 0 && (
        <div className="p-3 bg-white rounded border border-gray-300">
          <h4 className="text-sm font-bold text-gray-700 mb-2 uppercase tracking-wide">Detection Reasons</h4>
          <ul className="space-y-1">
            {email.reasons.slice(0, 10).map((reason: string, idx: number) => (
              <li key={idx} className="text-xs text-gray-700 flex">
                <span className="mr-2">•</span>
                <span>{reason}</span>
              </li>
            ))}
            {email.reasons.length > 10 && (
              <li className="text-xs text-gray-500 italic">+{email.reasons.length - 10} more reasons</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
};

export default ScoreBreakdown;
