import React, { useState } from 'react';
import CircularRiskScore from './CircularRiskScore';

interface ThreatItem {
  label: string;
  risk: string;
}

interface EmailDetailPageProps {
  email: any;
  onBack: () => void;
}

const EmailDetailPage: React.FC<EmailDetailPageProps> = ({ email, onBack }) => {
  const threats: ThreatItem[] = email.reasons?.slice(0, 4).map((reason: string) => ({
    label: reason.substring(0, 40),
    risk: email.final_score >= 0.8 ? 'High Risk' : email.final_score >= 0.65 ? 'Moderate Risk' : 'Low Risk',
  })) || [];

  const riskLevel = email.risk_level || (email.final_score >= 0.8 ? 'CRITICAL' : email.final_score >= 0.65 ? 'HIGH' : 'LOW');

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Header */}
      <div className="bg-gradient-to-r from-slate-900 to-slate-800 border-b border-gray-700 px-6 py-4 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={onBack}
              className="p-2 hover:bg-slate-700 rounded-lg transition-colors"
            >
              ← Back
            </button>
            <h1 className="text-2xl font-bold text-white">📧 Email Analysis</h1>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm text-gray-400">Status</div>
              <div className={`text-lg font-bold ${email.final_score >= 0.65 ? 'text-red-400' : 'text-green-400'}`}>
                {riskLevel}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Email List / Info */}
        <div className="lg:col-span-1">
          <div className="bg-slate-800/60 border border-gray-700 rounded-xl p-6 backdrop-blur-sm">
            <h2 className="section-title">Email Inbox</h2>
            <p className="text-sm text-gray-400 mb-6">Scanning Last 10 Messages</p>

            {/* Email Categories */}
            <div className="space-y-3">
              {/* Phishing Emails */}
              <div className="p-4 bg-red-900/20 border border-red-700/50 rounded-lg cursor-pointer hover:bg-red-900/30 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">⚠️</span>
                    <div>
                      <div className="font-semibold text-red-200">Phishing Emails</div>
                      <div className="text-xs text-red-400">{email.final_score >= 0.65 ? '4' : '2'}</div>
                    </div>
                  </div>
                  <span className="text-gray-500">›</span>
                </div>
              </div>

              {/* Safe Emails */}
              <div className="p-4 bg-green-900/20 border border-green-700/50 rounded-lg cursor-pointer hover:bg-green-900/30 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">✓</span>
                    <div>
                      <div className="font-semibold text-green-200">Safe Emails</div>
                      <div className="text-xs text-green-400">6</div>
                    </div>
                  </div>
                  <span className="text-gray-500">›</span>
                </div>
              </div>

              {/* Current Email */}
              <div className="p-4 bg-blue-900/20 border border-blue-700/50 rounded-lg">
                <div className="font-semibold text-blue-200 mb-2">Current Email</div>
                <div className="text-sm text-gray-300 mb-1 truncate">{email.subject}</div>
                <div className="text-xs text-gray-500 truncate">{email.sender}</div>
              </div>
            </div>

            {/* Email Stats */}
            <div className="mt-6 pt-6 border-t border-gray-700">
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Fetch Time</span>
                  <span className="text-gray-200">{(email.fetch_time_ms || 0).toFixed(0)}ms</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">Analysis Time</span>
                  <span className="text-gray-200">{(email.model_time_ms || 0).toFixed(0)}ms</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-gray-400">AI Analysis</span>
                  <span className="text-gray-200">{(email.groq_time_ms || 0).toFixed(0)}ms</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Risk Analysis */}
        <div className="lg:col-span-2">
          {/* Risk Score Circle */}
          <div className="bg-slate-800/60 border border-gray-700 rounded-xl p-8 backdrop-blur-sm mb-6">
            <CircularRiskScore score={email.final_score || 0} riskLevel={riskLevel} />
          </div>

          {/* Threat Analysis */}
          {threats.length > 0 && (
            <div className="bg-slate-800/60 border border-gray-700 rounded-xl p-6 backdrop-blur-sm mb-6">
              <h3 className="text-lg font-bold text-white mb-4">🚨 Threat Analysis</h3>
              <div className="space-y-3">
                {threats.map((threat, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                    <span className="text-gray-200 text-sm">{threat.label}</span>
                    <span
                      className={`px-3 py-1 rounded text-xs font-bold ${
                        threat.risk === 'High Risk'
                          ? 'bg-red-600 text-white'
                          : threat.risk === 'Moderate Risk'
                          ? 'bg-orange-600 text-white'
                          : 'bg-green-600 text-white'
                      }`}
                    >
                      {threat.risk}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI Explanation */}
          {email.ai_analysis?.explanation && (
            <div className="bg-slate-800/60 border border-gray-700 rounded-xl p-6 backdrop-blur-sm mb-6">
              <h3 className="text-lg font-bold text-white mb-3">💡 AI Explanation</h3>
              <p className="text-gray-300 text-sm leading-relaxed">{email.ai_analysis.explanation}</p>
            </div>
          )}

          {/* Security Tip */}
          <div className="bg-blue-900/30 border border-blue-700/50 rounded-xl p-6">
            <h3 className="text-lg font-bold text-blue-200 mb-3">🛡️ Security Tip</h3>
            <p className="text-blue-100 text-sm leading-relaxed">
              Avoid clicking on urgent links. Always verify the sender's address before taking action. Hover over links to see their actual destination.
            </p>
          </div>

          {/* Full Details */}
          <div className="mt-6 bg-slate-800/60 border border-gray-700 rounded-xl p-6 backdrop-blur-sm">
            <h3 className="text-lg font-bold text-white mb-4">📊 Full Analysis Report</h3>
            
            {/* Score Components */}
            {email.components && (
              <div className="grid grid-cols-2 gap-4 mb-6">
                {Object.entries(email.components).map(([key, value]: [string, any]) => {
                  if (typeof value !== 'number' || value === null) return null;
                  const percentage = Math.round(value * 100);
                  return (
                    <div key={key} className="p-3 bg-slate-700/50 rounded-lg">
                      <div className="text-xs text-gray-400 uppercase font-semibold mb-2">
                        {key.replace(/_/g, ' ')}
                      </div>
                      <div className="text-2xl font-bold text-white">{percentage}%</div>
                      <div className="h-1 bg-gray-700 rounded-full mt-2 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-red-500 to-red-600"
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Detection Reasons */}
            {email.reasons && email.reasons.length > 0 && (
              <div>
                <div className="text-sm font-semibold text-gray-300 mb-3">Detection Reasons:</div>
                <ul className="space-y-2 max-h-48 overflow-y-auto">
                  {email.reasons.slice(0, 8).map((reason: string, idx: number) => (
                    <li key={idx} className="flex gap-2 text-sm text-gray-400">
                      <span className="text-red-500 flex-shrink-0">•</span>
                      <span>{reason}</span>
                    </li>
                  ))}
                  {email.reasons.length > 8 && (
                    <li className="text-sm text-gray-500 italic">+{email.reasons.length - 8} more</li>
                  )}
                </ul>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailDetailPage;
