
import React, { useState } from 'react';
import { analyzeEmail } from '../api';
import ScoreBreakdown from './ScoreBreakdown';
import AnalysisReport from './AnalysisReport';

export default function DetectionForm({ onDetect }: { onDetect?: (result: any) => void }) {
  const [emailText, setEmailText] = useState('');
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [urls, setUrls] = useState('');
  const [headers, setHeaders] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleDetect = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      let urlsArr = urls ? urls.split(',').map(u => u.trim()) : undefined;
      let headersObj = undefined;
      try {
        headersObj = headers ? JSON.parse(headers) : undefined;
      } catch {
        headersObj = undefined;
      }
      const detection = await analyzeEmail(
        emailText,
        sender || undefined,
        urlsArr,
        headersObj
      );
      setResult(detection);
      if (onDetect) onDetect(detection);
    } catch (err) {
      setError(`Error analyzing email: ${err}`);
      console.error('Analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full">
      {/* Form Section */}
      <div className="w-full bg-white shadow rounded p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4">📧 Manual Email Analysis</h2>
        <form onSubmit={handleDetect} className="space-y-4">
          <input
            className="w-full border rounded p-3 text-sm"
            placeholder="Subject (optional)"
            value={subject}
            onChange={e => setSubject(e.target.value)}
          />
          <textarea
            className="w-full border rounded p-3 text-sm font-mono"
            rows={6}
            placeholder="Paste email text here..."
            value={emailText}
            onChange={e => setEmailText(e.target.value)}
            required
          />
          <input
            className="w-full border rounded p-3 text-sm"
            placeholder="Sender email (optional)"
            value={sender}
            onChange={e => setSender(e.target.value)}
          />
          <input
            className="w-full border rounded p-3 text-sm"
            placeholder="URLs (comma separated, optional)"
            value={urls}
            onChange={e => setUrls(e.target.value)}
          />
          <input
            className="w-full border rounded p-3 text-sm font-mono"
            placeholder='Email headers (JSON format, optional)'
            value={headers}
            onChange={e => setHeaders(e.target.value)}
          />
          <button
            type="submit"
            className="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-3 rounded-lg hover:from-blue-700 hover:to-blue-800 transition-all duration-300 font-semibold shadow-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? '⏳ Analyzing...' : '🔍 Analyze Email'}
          </button>
        </form>
        {error && (
          <div className="mt-4 p-3 bg-red-100 border border-red-400 rounded text-red-800 text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Score Breakdown Section */}
      {result && (
        <>
          {/* Primary Visual Report */}
          <AnalysisReport email={result} />
          
          {/* Optional: ScoreBreakdown for quick reference */}
          <div className="mt-8">
            <ScoreBreakdown email={result} />
          </div>
          
          {/* Quick Stats Summary */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-white rounded-lg shadow p-4 text-center">
              <div className="text-gray-600 text-sm font-semibold mb-2">🎯 Final Score</div>
              <div className="text-3xl font-bold text-blue-600">
                {((result.final_score || 0) * 100).toFixed(1)}%
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-4 text-center">
              <div className="text-gray-600 text-sm font-semibold mb-2">🧠 NLP Score</div>
              <div className="text-3xl font-bold text-purple-600">
                {((result.nlp_score || 0) * 100).toFixed(0)}%
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-4 text-center">
              <div className="text-gray-600 text-sm font-semibold mb-2">🔗 Link Score</div>
              <div className="text-3xl font-bold text-orange-600">
                {((result.link_score || 0) * 100).toFixed(0)}%
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow p-4 text-center">
              <div className="text-gray-600 text-sm font-semibold mb-2">📧 Auth Score</div>
              <div className="text-3xl font-bold text-green-600">
                {((result.header_score || 0) * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          {/* Detailed Component Breakdown */}
          {result.components && (
            <div className="bg-white rounded-lg shadow p-6 mb-6">
              <h3 className="text-lg font-bold mb-4">🔧 ML Model Scores</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {result.components.url_score !== undefined && (
                  <div className="p-4 bg-gradient-to-br from-red-50 to-red-100 rounded-lg border border-red-200">
                    <div className="text-sm font-semibold text-red-900">URL Model</div>
                    <div className="text-2xl font-bold text-red-600 mt-1">
                      {((result.components.url_score || 0) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-red-700 mt-1">Suspicious URL detection</div>
                  </div>
                )}
                
                {result.components.domain_score !== undefined && (
                  <div className="p-4 bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg border border-blue-200">
                    <div className="text-sm font-semibold text-blue-900">Domain Model</div>
                    <div className="text-2xl font-bold text-blue-600 mt-1">
                      {((result.components.domain_score || 0) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-blue-700 mt-1">Domain spoofing detection</div>
                  </div>
                )}
                
                {result.components.intent_score !== undefined && (
                  <div className="p-4 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg border border-yellow-200">
                    <div className="text-sm font-semibold text-yellow-900">Intent Model</div>
                    <div className="text-2xl font-bold text-yellow-600 mt-1">
                      {((result.components.intent_score || 0) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-yellow-700 mt-1">Phishing intent</div>
                  </div>
                )}
                
                {result.components.text_score !== undefined && (
                  <div className="p-4 bg-gradient-to-br from-purple-50 to-purple-100 rounded-lg border border-purple-200">
                    <div className="text-sm font-semibold text-purple-900">Text Model</div>
                    <div className="text-2xl font-bold text-purple-600 mt-1">
                      {((result.components.text_score || 0) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-purple-700 mt-1">Content analysis</div>
                  </div>
                )}
                
                {result.components.vt_score !== null && result.components.vt_score !== undefined && (
                  <div className="p-4 bg-gradient-to-br from-green-50 to-green-100 rounded-lg border border-green-200">
                    <div className="text-sm font-semibold text-green-900">VirusTotal</div>
                    <div className="text-2xl font-bold text-green-600 mt-1">
                      {((result.components.vt_score || 0) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-green-700 mt-1">70+ AV engines</div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Detection Reasons */}
          {result.reasons && result.reasons.length > 0 && (
            <div className="bg-white rounded-lg shadow p-6 mb-6">
              <h3 className="text-lg font-bold mb-4">🚨 Detection Reasons ({result.reasons.length})</h3>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {result.reasons.map((reason: string, idx: number) => (
                  <div key={idx} className="flex items-start gap-3 p-3 bg-gray-50 rounded">
                    <span className="text-red-500 font-bold flex-shrink-0">•</span>
                    <span className="text-sm text-gray-700">{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Highlighted Content */}
          {result.highlight && (result.highlight.urls?.length > 0 || result.highlight.phrases?.length > 0) && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-bold mb-4">🎯 Highlighted Threats</h3>
              
              {result.highlight.urls && result.highlight.urls.length > 0 && (
                <div className="mb-4">
                  <div className="font-semibold text-red-700 mb-2">Suspicious URLs ({result.highlight.urls.length}):</div>
                  <div className="space-y-2">
                    {result.highlight.urls.map((url: string, idx: number) => (
                      <div key={idx} className="p-2 bg-red-50 rounded border-l-4 border-red-500 text-sm truncate text-red-800 font-mono">
                        {url}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              
              {result.highlight.phrases && result.highlight.phrases.length > 0 && (
                <div>
                  <div className="font-semibold text-orange-700 mb-2">Suspicious Phrases ({result.highlight.phrases.length}):</div>
                  <div className="flex flex-wrap gap-2">
                    {result.highlight.phrases.map((phrase: string, idx: number) => (
                      <span key={idx} className="px-3 py-1 bg-orange-100 text-orange-800 rounded-full text-xs font-semibold">
                        {phrase}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
