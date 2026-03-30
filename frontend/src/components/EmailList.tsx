import React from 'react';

interface EmailListProps {
  emails: any[];
  selected: number;
  onSelect: (idx: number) => void;
}

const getRiskColor = (risk: string | number | undefined) => {
  if (typeof risk === 'number') {
    risk = risk > 0.65 ? 'HIGH' : risk > 0.45 ? 'MEDIUM' : 'LOW';
  }
  const riskStr = String(risk || '').toUpperCase();
  if (riskStr === 'CRITICAL') return 'bg-red-600 text-red-100';
  if (riskStr === 'HIGH') return 'bg-orange-600 text-orange-100';
  if (riskStr === 'MEDIUM') return 'bg-yellow-600 text-yellow-100';
  if (riskStr === 'LOW' || riskStr === 'SAFE') return 'bg-green-600 text-green-100';
  return 'bg-gray-600 text-gray-100';
};

const ScoreChip = ({ label, score }: { label: string; score: number | undefined }) => {
  if (score === undefined || score === null) return null;
  const color = score > 0.7 ? 'bg-red-600/30 text-red-200 border-red-600' : score > 0.5 ? 'bg-orange-600/30 text-orange-200 border-orange-600' : score > 0.3 ? 'bg-yellow-600/30 text-yellow-200 border-yellow-600' : 'bg-green-600/30 text-green-200 border-green-600';
  return (
    <span className={`text-xs px-2 py-1 rounded font-semibold border ${color}`} title={label}>
      {label}: {(score * 100).toFixed(0)}%
    </span>
  );
};

const EmailList: React.FC<EmailListProps> = ({ emails, selected, onSelect }) => {
  // Categorize emails
  const phishingEmails = emails.filter(e => (e.final_score || 0) >= 0.65);
  const safeEmails = emails.filter(e => (e.final_score || 0) < 0.45);

  return (
    <div className="w-full bg-black p-6 rounded-lg border-2 border-cyan-500/50 h-full flex flex-col overflow-hidden"
      style={{
        boxShadow: '0 0 30px rgba(34, 211, 238, 0.3), inset 0 0 20px rgba(34, 211, 238, 0.05)',
        background: 'linear-gradient(135deg, #0a0e27 0%, #0f1419 50%, #0a0e27 100%)'
      }}>
      
      <div className="mb-6 pb-4 border-b-2 border-cyan-600/40">
        <h2 className="text-lg font-mono font-bold text-cyan-300" style={{ textShadow: '0 0 10px rgba(34, 211, 238, 0.6)' }}>
          &gt; EMAIL_INBOX
        </h2>
        <p className="text-xs text-cyan-400 font-mono mt-1">scan_mode: ACTIVE | threads: {emails.length}</p>
      </div>

      <div className="space-y-3 flex-1 overflow-y-auto">
        {/* Phishing Emails Category */}
        <div 
          onClick={() => phishingEmails.length > 0 && onSelect(emails.indexOf(phishingEmails[0]))}
          className="p-3 bg-black/40 border-l-4 border-red-500 cursor-pointer hover:bg-red-600/10 transition-all group"
          style={{
            boxShadow: '0 0 15px rgba(239, 68, 68, 0.2), inset 0 0 10px rgba(239, 68, 68, 0.02)'
          }}>
          <div className="flex items-center justify-between">
            <div className="font-mono text-sm">
              <div className="text-red-300"><span className="text-red-500 font-bold">[THREAT]</span> {phishingEmails.length} emails detected</div>
              <div className="text-xs text-red-500 mt-1">Risk Level: CRITICAL</div>
            </div>
            <span className="text-red-400 group-hover:translate-x-1 transition-transform">›</span>
          </div>
        </div>

        {/* Safe Emails Category */}
        <div 
          onClick={() => safeEmails.length > 0 && onSelect(emails.indexOf(safeEmails[0]))}
          className="p-3 bg-black/40 border-l-4 border-emerald-500 cursor-pointer hover:bg-emerald-600/10 transition-all group"
          style={{
            boxShadow: '0 0 15px rgba(16, 185, 129, 0.2), inset 0 0 10px rgba(16, 185, 129, 0.02)'
          }}>
          <div className="flex items-center justify-between">
            <div className="font-mono text-sm">
              <div className="text-emerald-300"><span className="text-emerald-500 font-bold">[SAFE]</span> {safeEmails.length} verified emails</div>
              <div className="text-xs text-emerald-500 mt-1">Risk Level: LOW</div>
            </div>
            <span className="text-emerald-400 group-hover:translate-x-1 transition-transform">›</span>
          </div>
        </div>

        {/* Individual Emails - Tech Grid */}
        <div className="mt-6 pt-4 border-t-2 border-cyan-600/40">
          <p className="text-xs text-cyan-400 font-mono mb-3 flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-cyan-400 animate-pulse"></span>
            EMAIL_QUEUE ({emails.length})
          </p>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {emails.map((email, idx) => {
              const score = (email.final_score || 0) * 100;
              const riskStatus = score >= 65 ? '[THREAT]' : score >= 45 ? '[CAUTION]' : '[SAFE]';
              const riskColor = score >= 65 ? 'text-red-400 border-red-500/50' : score >= 45 ? 'text-orange-400 border-orange-500/50' : 'text-emerald-400 border-emerald-500/50';
              
              return (
                <div
                  key={idx}
                  onClick={() => onSelect(idx)}
                  className={`p-2 rounded font-mono text-xs cursor-pointer transition-all ${
                    selected === idx 
                      ? 'border border-cyan-400 bg-cyan-600/10' 
                      : 'border border-slate-700 hover:border-cyan-600/50 bg-black/20 hover:bg-cyan-600/5'
                  }`}
                  style={{
                    boxShadow: selected === idx 
                      ? '0 0 15px rgba(34, 211, 238, 0.3)'
                      : 'none'
                  }}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <div className="text-cyan-300 truncate">&gt; {email.subject.substring(0, 40)}</div>
                      <div className="text-cyan-500/70 text-xs truncate mt-0.5">{email.sender.substring(0, 35)}</div>
                    </div>
                    <span className={`${riskColor} border px-1.5 py-0.5 whitespace-nowrap`}
                      style={{ boxShadow: '0 0 8px currentColor' }}>
                      {score.toFixed(0)}%
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {emails.length === 0 && (
        <div className="text-center text-cyan-500/50 py-8 font-mono text-xs">
          &gt; No emails loaded. Run scan_inbox()
        </div>
      )}
    </div>
  );
};

export default EmailList;
