import React, { useState } from 'react';

interface ActionButtonsProps {
  riskScore: number;
  onMarkSafe?: () => void;
  onQuarantine?: () => void;
  onReport?: () => void;
}

export default function ActionButtons({ riskScore, onMarkSafe, onQuarantine, onReport }: ActionButtonsProps) {
  const [activeAction, setActiveAction] = useState<string | null>(null);

  const handleAction = (action: string, callback?: () => void) => {
    setActiveAction(action);
    callback?.();
    setTimeout(() => setActiveAction(null), 2000);
  };

  const isSuspicious = riskScore > 0.6;

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-bold text-white flex items-center gap-2">
        <span className="text-2xl">⚡</span> Recommended Actions
      </h3>

      <div className="grid grid-cols-3 gap-4">
        {/* Mark as Safe Button */}
        <button
          onClick={() => handleAction('safe', onMarkSafe)}
          disabled={isSuspicious}
          className={`px-6 py-4 rounded-lg font-semibold transition-all duration-300 flex flex-col items-center gap-2 border-2 backdrop-blur-sm ${
            activeAction === 'safe'
              ? 'bg-green-500/50 border-green-500 text-green-100 shadow-lg shadow-green-500/30'
              : isSuspicious
              ? 'bg-slate-700/30 border-slate-600 text-slate-500 cursor-not-allowed opacity-50'
              : 'bg-green-900/30 border-green-500/50 text-green-300 hover:bg-green-900/50 hover:border-green-400 hover:shadow-lg hover:shadow-green-500/20'
          }`}
        >
          <span className="text-2xl">✅</span>
          <span className="text-sm">Mark as Safe</span>
        </button>

        {/* Quarantine Button */}
        <button
          onClick={() => handleAction('quarantine', onQuarantine)}
          className={`px-6 py-4 rounded-lg font-semibold transition-all duration-300 flex flex-col items-center gap-2 border-2 backdrop-blur-sm ${
            activeAction === 'quarantine'
              ? 'bg-yellow-500/50 border-yellow-500 text-yellow-100 shadow-lg shadow-yellow-500/30'
              : 'bg-yellow-900/30 border-yellow-500/50 text-yellow-300 hover:bg-yellow-900/50 hover:border-yellow-400 hover:shadow-lg hover:shadow-yellow-500/20'
          }`}
        >
          <span className="text-2xl">⚠️</span>
          <span className="text-sm">Quarantine</span>
        </button>

        {/* Report to SOC Button */}
        <button
          onClick={() => handleAction('report', onReport)}
          className={`px-6 py-4 rounded-lg font-semibold transition-all duration-300 flex flex-col items-center gap-2 border-2 backdrop-blur-sm ${
            activeAction === 'report'
              ? 'bg-red-500/50 border-red-500 text-red-100 shadow-lg shadow-red-500/30'
              : 'bg-red-900/30 border-red-500/50 text-red-300 hover:bg-red-900/50 hover:border-red-400 hover:shadow-lg hover:shadow-red-500/20'
          }`}
        >
          <span className="text-2xl">🚨</span>
          <span className="text-sm">Report to SOC</span>
        </button>
      </div>

      {/* Info Box */}
      <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 text-xs text-slate-400">
        <p className="flex items-center gap-2">
          <span>ℹ️</span>
          {isSuspicious
            ? 'This email has a high risk score. It may be safer to quarantine it.'
            : 'This email appears legitimate. Actions are awaiting your confirmation.'}
        </p>
      </div>
    </div>
  );
}
