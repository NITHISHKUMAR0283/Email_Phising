import React, { useState } from 'react';
// Only use /analyze-email endpoint for new backend
import { analyzeEmail } from '../api';


export default function DetectionForm({ onDetect }: { onDetect?: (result: any) => void }) {
  const [emailText, setEmailText] = useState('');
  const [sender, setSender] = useState('');
  const [urls, setUrls] = useState('');
  const [headers, setHeaders] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleDetect = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    let urlsArr = urls ? urls.split(',').map(u => u.trim()) : undefined;
    let headersObj = undefined;
    try {
      headersObj = headers ? JSON.parse(headers) : undefined;
    } catch {
      headersObj = undefined;
    }
    const detection = await analyzeEmail(emailText, sender, urlsArr, headersObj);
    setResult(detection);
    if (onDetect) onDetect(detection);
    setLoading(false);
  };

  return (
    <div className="w-full max-w-xl bg-white shadow rounded p-6 mb-8">
      <h2 className="text-xl font-semibold mb-4">Phishing Detection</h2>
      <form onSubmit={handleDetect} className="space-y-4">
        <textarea
          className="w-full border rounded p-2"
          rows={4}
          placeholder="Paste email text here..."
          value={emailText}
          onChange={e => setEmailText(e.target.value)}
          required
        />
        <input
          className="w-full border rounded p-2"
          placeholder="Sender (optional)"
          value={sender}
          onChange={e => setSender(e.target.value)}
        />
        <input
          className="w-full border rounded p-2"
          placeholder="URLs (comma separated, optional)"
          value={urls}
          onChange={e => setUrls(e.target.value)}
        />
        <input
          className="w-full border rounded p-2"
          placeholder='Headers (JSON, optional)'
          value={headers}
          onChange={e => setHeaders(e.target.value)}
        />
        <button
          type="submit"
          className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          disabled={loading}
        >
          {loading ? 'Analyzing...' : 'Detect Phishing'}
        </button>
      </form>
      {result && (
        <div className="mt-6">
          <div className="mb-2">
            <span className="font-bold">Risk Score:</span> <span className={`font-semibold ${result.risk_score === 'High' ? 'text-red-600' : result.risk_score === 'Medium' ? 'text-yellow-600' : 'text-green-600'}`}>{result.risk_score}</span>
          </div>
          <div className="mb-2">
            <span className="font-bold">Phishing Probability:</span> {result.model_probs && (result.model_probs.phishing * 100).toFixed(1)}%
          </div>
          <div className="mb-2">
            <span className="font-bold">Heuristics:</span> {result.heuristics && result.heuristics.length > 0 ? result.heuristics.join(', ') : 'None'}
          </div>
          {Array.isArray(result.highlighted_tokens) && result.highlighted_tokens.length > 0 && (
            <div className="mb-2">
              <span className="font-bold">Highlighted Tokens:</span> {result.highlighted_tokens.join(', ')}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
