import React from 'react';
import { Activity, TrendingUp, Award, AlertTriangle, CheckCircle2, BarChart3 } from 'lucide-react';
import { getRiskStyle } from '../utils/theme';

/**
 * ===================================================================
 * CYBERSECURITY DASHBOARD - COMMAND CENTER EDITION
 * ===================================================================
 * 
 * THEME: High-density, authoritative data dashboard
 * PALETTE: Slate-950 base | Cyan-400 accents | Rose-600 threats | Emerald-500 safe
 * STRUCTURE: Header → Metrics Bar → Dense Data Table
 * TYPOGRAPHY: Inter (UI) + Mono (technical data)
 */

export default function Dashboard({ analyses, quizHistory }: { analyses: any[]; quizHistory: any[] }) {
  // ========== STATE & CALCULATIONS ==========
  const total = quizHistory.length;
  const mistakes = quizHistory.filter(q => q.mistake).length;
  const riskScore = total ? Math.round((mistakes / total) * 100) : 0;
  const accuracy = total > 0 ? Math.round(((total - mistakes) / total) * 100) : 0;
  
  // Categorize analyses
  const highRiskAnalyses = analyses.filter(a => (a.risk_score || 0) > 0.65);
  const lowRiskAnalyses = analyses.filter(a => (a.risk_score || 0) <= 0.45);
  const recentAnalyses = analyses.slice(-8);
  const recentQuiz = quizHistory.slice(-8);

  // ========== HELPER: Risk Status Badge ==========
  const getRiskBadge = (score: number) => {
    if (score > 0.65) {
      return { icon: AlertTriangle, color: 'text-rose-500', bg: 'bg-rose-500/10', label: 'CRITICAL' };
    } else if (score > 0.45) {
      return { icon: TrendingUp, color: 'text-amber-500', bg: 'bg-amber-500/10', label: 'MEDIUM' };
    } else {
      return { icon: CheckCircle2, color: 'text-emerald-500', bg: 'bg-emerald-500/10', label: 'SAFE' };
    }
  };

  return (
    <div className="w-full bg-gradient-to-b from-slate-950 to-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      
      {/* ============= HEADER SECTION ============= */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            <h1 className="text-lg font-semibold text-slate-100 tracking-tight">
              Security Posture Dashboard
            </h1>
          </div>
          <div className="text-xs font-mono text-slate-400">
            {new Date().toLocaleTimeString('en-US', { hour12: false })}
          </div>
        </div>
      </header>

      <div className="p-6 space-y-6">
        
        {/* ============= METRICS BAR (High-Density) ============= */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {/* Metric 1: Risk Score */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Risk Score</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="space-y-2">
              <div className={`text-3xl font-mono font-bold ${riskScore > 60 ? 'text-rose-400' : riskScore > 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {riskScore} %
              </div>
              <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all ${riskScore > 60 ? 'bg-rose-500' : riskScore > 40 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                  style={{ width: `${riskScore}%` }}
                />
              </div>
            </div>
          </div>

          {/* Metric 2: High Risk Analyses */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">High Risk</span>
              <AlertTriangle className="w-4 h-4 text-rose-500" />
            </div>
            <div className="text-3xl font-mono font-bold text-rose-400">
              {highRiskAnalyses.length}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {((highRiskAnalyses.length / (analyses.length || 1)) * 100).toFixed(0)}% of total
            </div>
          </div>

          {/* Metric 3: Low Risk Analyses */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Safe</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            </div>
            <div className="text-3xl font-mono font-bold text-emerald-400">
              {lowRiskAnalyses.length}
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {((lowRiskAnalyses.length / (analyses.length || 1)) * 100).toFixed(0)}% of total
            </div>
          </div>

          {/* Metric 4: Quiz Accuracy */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Accuracy</span>
              <Award className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-3xl font-mono font-bold text-cyan-400">
              {accuracy} %
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {quizHistory.length} attempts
            </div>
          </div>
        </section>

        {/* ============= DUAL DATA TABLE SECTION ============= */}
        <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* LEFT: Recent Analyses Table */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-lg overflow-hidden">
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                Recent Analyses
              </h2>
            </div>
            
            <div className="divide-y divide-slate-800 max-h-80 overflow-y-auto">
              {recentAnalyses.length > 0 ? (
                recentAnalyses.map((a, i) => {
                  const score = (a.risk_score || 0);
                  const badge = getRiskBadge(score);
                  const BadgeIcon = badge.icon;
                  
                  return (
                    <div
                      key={i}
                      className="px-4 py-3 hover:bg-slate-900/60 transition-colors border-l-2 border-slate-800 hover:border-slate-700"
                    >
                      <div className="flex items-center justify-between gap-3 mb-1">
                        <div className="flex items-center gap-2 flex-1 min-w-0">
                          <BadgeIcon className={`w-4 h-4 flex-shrink-0 ${badge.color}`} />
                          <span className="text-xs font-mono text-slate-300 truncate">
                            {a.reason || 'Analysis'}
                          </span>
                        </div>
                        <span className={`text-xs font-mono font-bold ${badge.color}`}>
                          {(score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="text-xs text-slate-500 truncate ml-6">
                        Score: {badge.label}
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="px-4 py-8 text-center text-slate-500 text-sm">
                  No analyses available
                </div>
              )}
            </div>
          </div>

          {/* RIGHT: Quiz History Table */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-lg overflow-hidden">
            <div className="bg-slate-950 px-4 py-3 border-b border-slate-800">
              <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <Award className="w-4 h-4 text-cyan-400" />
                Quiz History
              </h2>
            </div>
            
            <div className="divide-y divide-slate-800 max-h-80 overflow-y-auto">
              {recentQuiz.length > 0 ? (
                recentQuiz.map((q, i) => (
                  <div
                    key={i}
                    className={`px-4 py-3 hover:bg-slate-900/60 transition-colors border-l-2 ${
                      q.mistake
                        ? 'border-rose-600/50 hover:border-rose-600'
                        : 'border-emerald-600/50 hover:border-emerald-600'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
                        {q.mistake ? (
                          <AlertTriangle className="w-4 h-4 text-rose-500" />
                        ) : (
                          <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                        )}
                        <span className="text-xs font-mono text-slate-300">
                          Q{(q.question_id || i + 1).toString().padStart(2, '0')}
                        </span>
                      </div>
                      <span
                        className={`text-xs font-mono font-bold uppercase tracking-wider ${
                          q.mistake ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {q.mistake ? 'Mistake' : 'Correct'}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="px-4 py-8 text-center text-slate-500 text-sm">
                  No quiz history available
                </div>
              )}
            </div>
          </div>
        </section>

        {/* ============= SUMMARY FOOTER ============= */}
        <section className="bg-slate-900/40 border border-slate-800 rounded-lg p-4">
          <div className="grid grid-cols-3 gap-4 text-xs">
            <div className="text-center">
              <div className="text-slate-400 font-mono uppercase tracking-wider mb-1">Total Analyses</div>
              <div className="text-2xl font-mono font-bold text-cyan-400">{analyses.length}</div>
            </div>
            <div className="text-center">
              <div className="text-slate-400 font-mono uppercase tracking-wider mb-1">Quiz Attempts</div>
              <div className="text-2xl font-mono font-bold text-cyan-400">{quizHistory.length}</div>
            </div>
            <div className="text-center">
              <div className="text-slate-400 font-mono uppercase tracking-wider mb-1">Thread Status</div>
              <div className="text-2xl font-mono font-bold text-emerald-400">Active</div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
