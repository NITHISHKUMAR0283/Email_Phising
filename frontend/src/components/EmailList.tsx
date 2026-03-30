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
  if (riskStr === 'CRITICAL') return 'bg-red-600 text-white';
  if (riskStr === 'HIGH') return 'bg-orange-500 text-white';
  if (riskStr === 'MEDIUM') return 'bg-yellow-500 text-white';
  if (riskStr === 'LOW' || riskStr === 'SAFE') return 'bg-green-500 text-white';
  return 'bg-gray-500 text-white';
};

const ScoreChip = ({ label, score }: { label: string; score: number | undefined }) => {
  if (score === undefined || score === null) return null;
  const color = score > 0.7 ? 'bg-red-100 text-red-800' : score > 0.5 ? 'bg-orange-100 text-orange-800' : score > 0.3 ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800';
  return (
    <span className={`text-xs px-2 py-1 rounded font-semibold ${color}`} title={label}>
      {label}: {(score * 100).toFixed(0)}%
    </span>
  );
};

const EmailList: React.FC<EmailListProps> = ({ emails, selected, onSelect }) => (
  <div className="w-full">
    <h2 className="font-bold text-lg mb-4">📧 Inbox</h2>
    <div className="space-y-2 max-h-96 overflow-y-auto">
      {emails.map((email, idx) => (
        <div
          key={idx}
          className={`p-3 cursor-pointer rounded border-2 transition ${
            selected === idx ? 'border-blue-500 bg-blue-50' : 'border-gray-200 hover:border-gray-400 bg-white'
          }`}
          onClick={() => onSelect(idx)}
        >
          {/* Subject and Risk Badge */}
          <div className="flex items-start justify-between mb-2">
            <div className="flex-1 pr-2">
              <div className="font-semibold text-sm truncate">{email.subject}</div>
              <div className="text-xs text-gray-500 truncate">{email.sender}</div>
            </div>
            <span className={`px-2 py-1 rounded text-xs font-bold whitespace-nowrap ${getRiskColor(email.risk_level || email.risk_score)}`}>
              {(email.final_score ? (email.final_score * 100).toFixed(0) : 'N/A')}%
            </span>
          </div>

          {/* Score Summary for Judges */}
          <div className="grid grid-cols-2 gap-1 text-xs">
            <ScoreChip label="AI" score={email.nlp_score} />
            <ScoreChip label="Link" score={email.link_score} />
            <ScoreChip label="Auth" score={email.header_score} />
            {email.components?.url_score !== undefined && (
              <span className="text-xs px-2 py-1 rounded bg-purple-100 text-purple-800 font-semibold" title="URL Score">
                URL: {(email.components.url_score * 100).toFixed(0)}%
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
    {emails.length === 0 && (
      <div className="text-center text-gray-400 py-8">No emails loaded yet. Fetch emails to see them here.</div>
    )}
  </div>
);

export default EmailList;
