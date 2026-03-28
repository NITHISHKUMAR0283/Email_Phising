
import React from 'react';
import RiskBadge from './RiskBadge';
import Quiz from './Quiz';

// Color map for highlights based on risk
const highlightColor: Record<string, string> = {
  High: 'bg-red-200 text-red-800',
  Medium: 'bg-yellow-200 text-yellow-800',
  Low: 'bg-green-200 text-green-800',
};

// Heuristic badge color
const heuristicColor: Record<string, string> = {
  'Suspicious URL': 'bg-orange-200 text-orange-800',
  'SPF failed': 'bg-pink-200 text-pink-800',
  'DKIM failed': 'bg-pink-100 text-pink-700',
  'DMARC failed': 'bg-pink-100 text-pink-700',
};

// Highlight risky tokens in the email body
function highlightText(text: string, highlights: string[], risk: string) {
  if (!highlights || highlights.length === 0) return text;
  let result = text;
  highlights.forEach(token => {
    const re = new RegExp(`(${token})`, 'gi');
    result = result.replace(re, '<mark class="' + (highlightColor[risk] || 'bg-yellow-200') + ' px-1 rounded">$1</mark>');
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
          className={`px-2 py-1 rounded text-xs font-semibold cursor-help ${heuristicColor[h] || 'bg-gray-200 text-gray-700'}`}
          title={h}
        >
          {h}
        </span>
      ))}
    </div>
  );
}

// Main EmailDetail component
const EmailDetail: React.FC<{ email: any }> = ({ email }) => (
  <div className="w-full bg-white rounded shadow p-4">
    <div className="flex items-center justify-between mb-2">
      <h2 className="font-bold text-lg break-all">{email.subject}</h2>
      <RiskBadge risk={email.risk_score} />
    </div>
    <div className="mb-2 text-xs text-gray-500">From: {email.sender}</div>
    <div className="mb-4 text-base leading-relaxed break-words">
      {highlightText(email.email_text, email.highlighted_tokens, email.risk_score)}
    </div>
    <div className="mb-2">
      <span className="font-semibold">Heuristics:</span>
      <HeuristicBadges heuristics={email.heuristics} />
    </div>
    {email.quiz && email.quiz.length > 0 && (
      <div className="mt-4">
        <Quiz quiz={email.quiz} />
      </div>
    )}
    <div className="text-xs text-gray-400 mt-2">Timestamp: {email.timestamp}</div>
  </div>
);

export default EmailDetail;
