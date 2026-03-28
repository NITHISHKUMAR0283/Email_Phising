
import React, { useState, useEffect } from 'react';
import axios from 'axios';

import { ExclamationTriangleSVG, TrashSVG } from './SimpleIcons';


const riskColorByLabel = (risk: string) => {
  if (risk === 'High') return 'bg-red-100 text-red-700 border-red-500';
  if (risk === 'Medium') return 'bg-orange-100 text-orange-700 border-orange-500';
  return 'bg-green-100 text-green-700 border-green-500';
};

function highlightTokens(text: string, tokens: string[], color: string) {
  if (!tokens || tokens.length === 0) return text;
  let result = text;
  tokens.forEach(token => {
    const re = new RegExp(`(${token})`, 'gi');
    result = result.replace(re, `<mark class=\"${color} px-1 rounded\">$1</mark>`);
  });
  return <span dangerouslySetInnerHTML={{ __html: result }} />;
}


export default function HighRiskInbox() {
  const [emails, setEmails] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const fetchEmails = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await axios.get('http://localhost:8000/fetch-high-risk-emails', { withCredentials: true });
      setEmails(res.data as any[]);
    } catch (e: any) {
      setError('Failed to fetch emails. Please sign in with Google.');
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchEmails();
  }, []);

  // Sort by phishing percentage (descending) and take top 10
  const getPhishingPercent = (email: any) => {
    // Try to parse from risk_score or phishingPercentage
    if (typeof email.phishingPercentage === 'number') return email.phishingPercentage;
    if (typeof email.risk_score === 'number') return email.risk_score;
    if (typeof email.risk_score === 'string' && email.risk_score.endsWith('%')) return parseInt(email.risk_score);
    if (typeof email.risk_score === 'string') return parseInt(email.risk_score.replace(/[^0-9]/g, ''));
    return 0;
  };
  const highRiskEmails = [...emails]
    .sort((a, b) => getPhishingPercent(b) - getPhishingPercent(a))
    .slice(0, 10);

  // Stat bar
  const totalScanned = emails.length;
  const highRiskFound = highRiskEmails.length;

  return (
    <div className="w-full max-w-3xl mx-auto mt-8 space-y-6">
      <div className="flex justify-between items-center mb-2">
        <h2 className="text-2xl font-bold text-gray-800">Top 10 Security Threats</h2>
        <button
          onClick={() => window.location.href = 'http://localhost:8000/login'}
          className="bg-blue-600 text-white px-4 py-2 rounded shadow hover:bg-blue-700"
        >
          Sign in with Google
        </button>
      </div>
      <div className="flex items-center gap-4 text-sm text-gray-600 bg-gray-100 px-4 py-2 rounded-lg">
        <span>Total Scanned: <span className="font-bold text-gray-900">{totalScanned}</span></span>
        <span>|</span>
        <span>High Risk Found: <span className="font-bold text-red-600">{highRiskFound}</span></span>
      </div>
      {loading && <div className="text-gray-600">Loading...</div>}
      {error && <div className="text-red-600 mb-2">{error}</div>}
      <div className="space-y-4">
        {highRiskEmails.map((email, i) => {
          // Use risk_score from API ('High', 'Medium', 'Low')
          const risk = typeof email.risk_score === 'string' ? email.risk_score : 'Low';
          return (
            <div key={i} className={`flex items-center justify-between p-4 bg-white rounded-xl shadow-sm border-l-4 ${risk === 'High' ? 'border-red-500' : risk === 'Medium' ? 'border-orange-500' : 'border-green-500'} hover:shadow-md transition`}>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-semibold text-gray-900 truncate">{email.sender}</span>
                  {risk === 'High' && <ExclamationTriangleSVG className="h-5 w-5 text-red-500" title="Critical risk" />}
                </div>
                <div className="text-sm text-gray-500 truncate">{email.subject}</div>
                <div className="mt-2 text-xs text-gray-700">
                  {highlightTokens(email.body, email.highlighted_tokens, risk === 'High' ? 'bg-red-200' : risk === 'Medium' ? 'bg-orange-200' : 'bg-green-200')}
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {email.heuristics && email.heuristics.map((h: string, j: number) => (
                    <span key={j} className="inline-flex items-center gap-1 bg-gray-200 text-gray-700 rounded px-2 py-1 text-xs" title={h}>
                      <ExclamationTriangleSVG className="h-3 w-3 text-yellow-500" />
                      {h}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex flex-col items-end gap-2 ml-4">
                <span className={`text-lg font-bold px-3 py-1 rounded-full border ${riskColorByLabel(risk)}`}>{risk} Risk</span>
                <button className="text-gray-400 hover:text-red-600" title="Quarantine/Delete (not implemented)"><TrashSVG className="h-5 w-5" /></button>
              </div>
            </div>
          );
        })}
        {highRiskEmails.length === 0 && !loading && (
          <div className="text-center text-gray-500 py-8">No high-risk emails found.</div>
        )}
      </div>
    </div>
  );
}
