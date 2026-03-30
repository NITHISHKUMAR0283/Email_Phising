import React from 'react';
import { getRiskStyle } from '../utils/theme';

export default function Dashboard({ analyses, quizHistory }: { analyses: any[]; quizHistory: any[] }) {
  // Calculate user risk score (simple: % of quiz mistakes)
  const total = quizHistory.length;
  const mistakes = quizHistory.filter(q => q.mistake).length;
  const riskScore = total ? Math.round((mistakes / total) * 100) : 0;

  return (
    <div className="w-full max-w-2xl card-dark mb-8">
      <div className="p-6">
        <h2 className="text-2xl font-bold text-white mb-6">📊 User Dashboard</h2>

        {/* Risk Score Card */}
        <div className="mb-8 p-4 bg-slate-900/60 rounded-lg border border-gray-700">
          <span className="text-gray-300 font-semibold">Cumulative User Risk Score:</span>
          <div className="flex items-center gap-4 mt-2">
            <div className={`text-4xl font-bold ${getRiskStyle(riskScore / 100).textColor}`}>
              {riskScore}%
            </div>
            <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${getRiskStyle(riskScore / 100).bgColor}`}
                style={{ width: `${riskScore}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Recent Analyses */}
          <div>
            <h3 className="text-lg font-bold text-white mb-4">📧 Recent Analyses</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto scrollbar-dark">
              {analyses.slice(-5).map((a, i) => (
                <div key={i} className="p-3 bg-slate-800/40 rounded border border-gray-700">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300 text-sm truncate">{a.reason || 'Analysis'}</span>
                    <span className={`px-2 py-1 rounded text-xs font-bold ${getRiskStyle(a.risk_score).bgColor} ${getRiskStyle(a.risk_score).textColor}`}>
                      {(typeof a.risk_score === 'number' ? (a.risk_score * 100).toFixed(0) : a.risk_score)}%
                    </span>
                  </div>
                </div>
              ))}
              {analyses.length === 0 && (
                <div className="text-center text-gray-500 py-4">No analyses yet</div>
              )}
            </div>
          </div>

          {/* Quiz History */}
          <div>
            <h3 className="text-lg font-bold text-white mb-4">🎯 Quiz History</h3>
            <div className="space-y-2 max-h-64 overflow-y-auto scrollbar-dark">
              {quizHistory.slice(-5).map((q, i) => (
                <div key={i} className={`p-3 rounded border ${q.mistake ? 'bg-red-900/20 border-red-700/50' : 'bg-green-900/20 border-green-700/50'}`}>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300 text-sm">Question {q.question_id || i + 1}</span>
                    <span className={`px-2 py-1 rounded text-xs font-bold ${q.mistake ? 'bg-red-600 text-red-100' : 'bg-green-600 text-green-100'}`}>
                      {q.mistake ? '❌ Mistake' : '✅ Correct'}
                    </span>
                  </div>
                </div>
              ))}
              {quizHistory.length === 0 && (
                <div className="text-center text-gray-500 py-4">No quiz history</div>
              )}
            </div>
          </div>
        </div>

        {/* Stats Summary */}
        <div className="mt-6 pt-6 border-t border-gray-700 grid grid-cols-3 gap-4">
          <div className="text-center p-3 bg-slate-900/40 rounded">
            <div className="text-gray-400 text-sm">Total Analyses</div>
            <div className="text-2xl font-bold text-white">{analyses.length}</div>
          </div>
          <div className="text-center p-3 bg-slate-900/40 rounded">
            <div className="text-gray-400 text-sm">Quiz Attempts</div>
            <div className="text-2xl font-bold text-white">{quizHistory.length}</div>
          </div>
          <div className="text-center p-3 bg-slate-900/40 rounded">
            <div className="text-gray-400 text-sm">Accuracy Rate</div>
            <div className={`text-2xl font-bold ${total > 0 && (total - mistakes) / total > 0.8 ? 'text-green-400' : 'text-red-400'}`}>
              {total > 0 ? Math.round(((total - mistakes) / total) * 100) : 0}%
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
