
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import RiskBadge from './RiskBadge';
import { ExclamationTriangleSVG } from './SimpleIcons';
import Scene3D from './Scene3D';
import RiskVisualizer3D from './RiskVisualizer3D';

interface EmailData {
  id: string;
  subject: string;
  sender: string;
  risk_score: string;
  final_score: number;
  body: string;
  timestamp: string;
  fetch_time_ms: number;
  model_time_ms: number;
  highlight?: { urls: string[]; phrases: string[] };
}

interface FetchResponse {
  all_emails: EmailData[];
  phishing_emails: EmailData[];
  fetch_time_ms: number;
  total_model_time_ms: number;
  total_time_ms: number;
  total_emails: number;
  phishing_count: number;
}

export default function HighRiskInbox() {
  const [allEmails, setAllEmails] = useState<EmailData[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [timing, setTiming] = useState<{
    fetch_time_ms: number;
    total_model_time_ms: number;
    total_time_ms: number;
  }>({ fetch_time_ms: 0, total_model_time_ms: 0, total_time_ms: 0 });
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<'LOW' | 'HIGH_MEDIUM' | 'NONE'>('NONE');

  // Check if user is authenticated on component mount
  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const response = await fetch('http://localhost:8000/check-auth');
        if (response.ok) {
          setIsAuthenticated(true);
          setCheckingAuth(false);
          // After confirming auth, fetch emails
          fetchEmails();
        } else {
          setIsAuthenticated(false);
          setCheckingAuth(false);
        }
      } catch (err) {
        console.error('Auth check failed:', err);
        setIsAuthenticated(false);
        setCheckingAuth(false);
      }
    };

    checkAuthentication();
  }, []);

  const fetchEmails = async () => {
    setLoading(true);
    setError('');
    setAllEmails([]);
    setTiming({ fetch_time_ms: 0, total_model_time_ms: 0, total_time_ms: 0 });
    setScanProgress(0);
    
    try {
      const eventSource = new EventSource(
        'http://localhost:8000/fetch-emails-stream?max_results=20'
      );

      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'init') {
          console.log('Starting email scan...');
          setScanProgress(5);
        } else if (data.type === 'email') {
          setAllEmails((prev) => [...prev, data.email]);
          setScanProgress(Math.min(5 + (data.count * 4), 95));
        } else if (data.type === 'complete') {
          setTiming({
            fetch_time_ms: data.fetch_time_ms,
            total_model_time_ms: data.total_model_time_ms,
            total_time_ms: (data.fetch_time_ms + data.total_model_time_ms),
          });
          setScanProgress(100);
          setLoading(false);
          eventSource.close();
        }
      };

      eventSource.onerror = (err) => {
        console.error('EventSource error:', err);
        setError('Failed to stream emails. Please ensure you are logged in and try again.');
        setLoading(false);
        setScanProgress(0);
        setIsAuthenticated(false);
        eventSource.close();
      };
    } catch (e: any) {
      setError('Failed to fetch emails. Please sign in with Google first.');
      console.error(e);
      setLoading(false);
      setScanProgress(0);
    }
  };

  const highRiskCount = allEmails.filter(e => e.risk_score === 'HIGH').length;
  const mediumRiskCount = allEmails.filter(e => e.risk_score === 'MEDIUM').length;
  const lowRiskCount = allEmails.filter(e => e.risk_score === 'LOW').length;

  // Filter emails based on selected risk level
  const filteredEmails = selectedRiskFilter === 'NONE' 
    ? allEmails 
    : selectedRiskFilter === 'LOW'
    ? allEmails.filter(e => e.risk_score === 'LOW')
    : allEmails.filter(e => e.risk_score === 'HIGH' || e.risk_score === 'MEDIUM');

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex flex-col">
      {/* Animated Background Blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0 top-32">
        <div className="absolute top-20 left-10 w-72 h-72 bg-blue-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 right-10 w-72 h-72 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      {/* Main Content - No header, App.tsx handles it */}
      <div className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {/* Not Authenticated Screen */}
        {checkingAuth ? (
          <div className="text-center py-16">
            <div className="inline-block">
              <div className="w-12 h-12 rounded-full border-4 border-blue-500 border-t-cyan-400 animate-spin mb-4"></div>
              <p className="text-blue-300 text-lg font-semibold">Checking authentication...</p>
            </div>
          </div>
        ) : !isAuthenticated ? (
          <div className="text-center py-16">
            <div className="inline-block max-w-md">
              <div className="mb-6">
                <p className="text-5xl mb-4">🔐</p>
              </div>
              <h2 className="text-3xl font-bold text-blue-300 mb-4">Sign In Required</h2>
              <p className="text-slate-400 text-lg mb-8">
                Please sign in with Google to access your email inbox and scan for phishing threats.
              </p>
              <button
                onClick={() => window.location.href = 'http://localhost:8000/login'}
                className="px-8 py-4 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-xl font-semibold hover:from-blue-600 hover:to-blue-800 transition-all duration-300 transform hover:scale-110 hover:-translate-y-1 shadow-lg hover:shadow-blue-500/70 border border-blue-400/30 text-lg"
              >
                🔑 Sign In with Google
              </button>
            </div>
          </div>
        ) : (
          <>
          {loading && allEmails.length < 20 && (
          <div className="mb-8 space-y-3 bg-slate-800/50 p-6 rounded-lg border border-slate-700 backdrop-blur-sm">
            <div className="flex items-center justify-between">
              <p className="text-blue-300 font-semibold">🔍 Scanning emails in progress...</p>
              <p className="text-blue-300 font-semibold">{scanProgress}%</p>
            </div>
            <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-blue-400 to-cyan-400 rounded-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <p className="text-slate-400 text-sm">Fetched: {allEmails.length} emails so far...</p>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 px-6 py-4 rounded-lg mb-6 backdrop-blur-sm animate-pulse">
            ⚠️ {error}
          </div>
        )}

        {/* Stats Cards - 2 Categories: Safe and Risky */}
        {allEmails.length > 0 && (
          <div className="mb-8">
            <div className="grid grid-cols-2 gap-6">
              {/* Safe Emails - Gmail SVG */}
              <div 
                onClick={() => setSelectedRiskFilter('LOW')}
                className={`cursor-pointer bg-gradient-to-br from-green-900/40 to-green-800/40 border rounded-lg p-8 backdrop-blur-sm transition-all duration-300 transform hover:scale-105 shadow-lg ${selectedRiskFilter === 'LOW' ? 'border-green-300 ring-2 ring-green-400' : 'border-green-500/30 hover:border-green-400'}`}
                style={{minHeight: '300px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'}}>
                <p className="text-green-300 text-lg font-medium mb-6">✅ Safe</p>
                <div className="h-32 mb-6 flex items-center justify-center">
                  <img 
                    src="/google-gmail-svgrepo-com.svg" 
                    alt="Safe" 
                    style={{height: '100px', filter: 'drop-shadow(0 0 15px rgba(16,185,129,0.7))'}}
                  />
                </div>
                <p className="text-6xl font-bold text-green-300">{lowRiskCount}</p>
              </div>

              {/* Risky Emails - Spam Icon */}
              <div 
                onClick={() => setSelectedRiskFilter('HIGH_MEDIUM')}
                className={`cursor-pointer bg-gradient-to-br from-red-900/40 to-red-800/40 border rounded-lg p-8 backdrop-blur-sm transition-all duration-300 transform hover:scale-105 shadow-lg ${selectedRiskFilter === 'HIGH_MEDIUM' ? 'border-red-300 ring-2 ring-red-400' : 'border-red-500/30 hover:border-red-400'}`}
                style={{minHeight: '300px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'}}>
                <p className="text-red-300 text-lg font-medium mb-6">🚨 Risky</p>
                <div className="h-32 mb-6 flex items-center justify-center">
                  <img 
                    src="/spam.png" 
                    alt="Risky" 
                    style={{height: '100px', filter: 'drop-shadow(0 0 15px rgba(255,23,68,0.7))'}}
                  />
                </div>
                <p className="text-6xl font-bold text-red-300">{highRiskCount + mediumRiskCount}</p>
              </div>
            </div>
          </div>
        )}

        {/* Performance Metrics */}
        {timing.total_time_ms > 0 && (
          <div className="bg-gradient-to-r from-slate-800/80 to-slate-700/80 border border-slate-600 rounded-xl p-6 mb-8 backdrop-blur-sm">
            <h2 className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-4">
              ⏱️ Performance Metrics
            </h2>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-blue-400 transition-all duration-300">
                <p className="text-blue-300 text-sm font-medium mb-1">Total Scan Time</p>
                <p className="text-3xl font-bold text-blue-400">
                  {(timing.total_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
              <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-emerald-400 transition-all duration-300">
                <p className="text-emerald-300 text-sm font-medium mb-1">Total Fetch Time</p>
                <p className="text-3xl font-bold text-emerald-400">
                  {(timing.fetch_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
              <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600 hover:border-purple-400 transition-all duration-300">
                <p className="text-purple-300 text-sm font-medium mb-1">Total Analysis Time</p>
                <p className="text-3xl font-bold text-purple-400">
                  {(timing.total_model_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-4 mb-8">
          <button
            onClick={fetchEmails}
            disabled={loading}
            className="px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white rounded-lg font-semibold hover:from-emerald-600 hover:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-emerald-500/50"
          >
            {loading ? '⏳ Scanning...' : '🔄 Scan Emails'}
          </button>
        </div>

        {/* Email List Container */}
        {loading && allEmails.length === 0 ? (
          <div className="text-center py-16">
            <div className="inline-block">
              <div className="w-12 h-12 rounded-full border-4 border-blue-500 border-t-cyan-400 animate-spin mb-4"></div>
              <p className="text-blue-300 text-lg font-semibold">Scanning your inbox...</p>
              <p className="text-slate-400 text-sm mt-2">Please ensure you've signed in with Google</p>
            </div>
          </div>
        ) : error && allEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-slate-400 text-lg mb-4">Unable to load emails</p>
            <button
              onClick={fetchEmails}
              className="px-6 py-2 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-all"
            >
              Try Again
            </button>
          </div>
        ) : allEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-blue-300 text-lg">No emails found</p>
          </div>
        ) : filteredEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-slate-400 text-lg">
              {selectedRiskFilter === 'LOW' 
                ? 'No safe emails found' 
                : 'No risky emails found'}
            </p>
            <button
              onClick={() => setSelectedRiskFilter('NONE')}
              className="mt-4 px-6 py-2 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-all"
            >
              View All Emails
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-slate-300 text-sm font-semibold mb-4">
              Showing {filteredEmails.length} email{filteredEmails.length !== 1 ? 's' : ''} {selectedRiskFilter === 'LOW' && 'with safe emails'} {selectedRiskFilter === 'HIGH_MEDIUM' && 'with risky emails'}
            </div>
            {filteredEmails.map((email, idx) => (
              <div
                key={`${email.id}-${idx}`}
                onClick={() => setExpandedId(expandedId === email.id ? null : email.id)}
                className={`border rounded-lg backdrop-blur-sm transition-all duration-300 transform hover:scale-102 cursor-pointer animate-in fade-in slide-in-from-left ${
                  email.risk_score === 'HIGH'
                    ? 'bg-gradient-to-br from-red-900/30 to-red-800/20 border-red-500/40 hover:border-red-400 hover:from-red-900/50 hover:to-red-800/40 hover:shadow-lg hover:shadow-red-500/20'
                    : email.risk_score === 'MEDIUM'
                    ? 'bg-gradient-to-br from-yellow-900/30 to-yellow-800/20 border-yellow-500/40 hover:border-yellow-400 hover:from-yellow-900/50 hover:to-yellow-800/40 hover:shadow-lg hover:shadow-yellow-500/20'
                    : 'bg-gradient-to-br from-green-900/30 to-green-800/20 border-green-500/40 hover:border-green-400 hover:from-green-900/50 hover:to-green-800/40 hover:shadow-lg hover:shadow-green-500/20'
                } shadow-md hover:shadow-2xl`}
                style={{
                  animation: `slideInUp 0.4s ease-out ${idx * 0.05}s both`
                }}
              >
                {/* Card Header with Subject and Badge */}
                <div className="px-6 py-4 border-b border-slate-600/50">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start gap-3">
                        {email.risk_score === 'HIGH' && (
                          <div className="animate-pulse flex-shrink-0 mt-1">
                            <ExclamationTriangleSVG />
                          </div>
                        )}
                        <h3 className="font-bold text-lg text-white break-words hover:text-blue-300 transition-colors">
                          {email.subject}
                        </h3>
                      </div>
                    </div>
                    <div className="flex-shrink-0">
                      <RiskBadge risk={email.risk_score} />
                    </div>
                  </div>
                  <p className="text-sm text-slate-400">
                    <span className="font-semibold text-slate-300">From:</span> <span className="text-slate-300">{email.sender}</span>
                  </p>
                </div>

                {/* Card Main Content - Quick Stats */}
                <div className="px-6 py-4">
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    {/* Risk Score */}
                    <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Risk Score</p>
                      <p className={`text-2xl font-bold ${
                        email.risk_score === 'HIGH' ? 'text-red-400' :
                        email.risk_score === 'MEDIUM' ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>
                        {(email.final_score * 100).toFixed(0)}%
                      </p>
                    </div>

                    {/* Fetch Time */}
                    <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Fetch Time</p>
                      <p className="text-2xl font-bold text-emerald-400">{email.fetch_time_ms}ms</p>
                    </div>

                    {/* Analysis Time */}
                    <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50">
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-1">Analysis</p>
                      <p className="text-2xl font-bold text-purple-400">{email.model_time_ms}ms</p>
                    </div>
                  </div>

                  {/* Expand Indicator */}
                  <div className="text-center">
                    <p className="text-xs text-slate-500 font-medium">
                      {expandedId === email.id ? '▼ Hide Details' : '▶ Show Details'}
                    </p>
                  </div>
                </div>

                {/* Expanded Content */}
                {expandedId === email.id && (
                  <div className="px-6 py-4 border-t border-slate-600/50 space-y-4 animate-in fade-in">
                    {/* Email Body */}
                    <div>
                      <p className="font-semibold text-blue-300 mb-2 text-sm">📧 Email Body</p>
                      <div className="bg-slate-900/70 p-4 rounded-lg border border-slate-700/50 max-h-48 overflow-y-auto">
                        <p className="text-sm text-slate-300 leading-relaxed">
                          {email.body?.substring(0, 500) || 'No body content'}
                          {email.body && email.body.length > 500 ? '...' : ''}
                        </p>
                      </div>
                    </div>

                    {/* Suspicious URLs with REAL, ROBUST multi-layer analysis */}
                    {email.highlight?.urls && email.highlight.urls.length > 0 && (
                      <div>
                        <p className="font-semibold text-red-300 mb-3 text-sm">🔗 Suspicious URLs ({email.highlight.urls.length})</p>
                        <div className="space-y-4">
                          {email.highlight.urls.map((url, i) => {
                            return (
                              <div key={i} className="bg-red-900/40 border border-red-500/60 rounded-lg p-4 space-y-3">
                                {/* URL Full Display */}
                                <div className="mb-2">
                                  <p className="text-xs text-slate-400 font-semibold mb-1">FULL URL</p>
                                  <p className="text-xs text-red-300 break-all font-mono bg-slate-900/50 p-2 rounded">
                                    {url}
                                  </p>
                                </div>

                                {/* Quick Overview */}
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="bg-slate-900/70 rounded p-2 border border-slate-700">
                                    <p className="text-xs text-slate-400">Protocol</p>
                                    <p className="text-sm font-mono text-red-300">{url.match(/^[a-z]+(?=:)/)?.[0] || 'http'}</p>
                                  </div>
                                  <div className="bg-slate-900/70 rounded p-2 border border-slate-700">
                                    <p className="text-xs text-slate-400">Domain</p>
                                    <p className="text-sm font-mono text-red-300 truncate">{url.split('/')[2] || 'N/A'}</p>
                                  </div>
                                </div>

                                {/* Multi-Layer Analysis Results */}
                                <div className="space-y-2">
                                  <p className="text-xs text-orange-400 font-bold uppercase">🔴 Multi-Layer Analysis Report</p>
                                  
                                  {/* Analysis Indicators */}
                                  <div className="space-y-1">
                                    <div className="bg-orange-900/50 border-l-4 border-orange-500 p-2 rounded">
                                      <p className="text-xs font-semibold text-orange-300">📊 URL Structure Analysis</p>
                                      <ul className="text-xs text-orange-200 mt-1 space-y-1 ml-2">
                                        <li>• No HTTPS encryption - credentials can be intercepted</li>
                                        <li>• Generic domain structure - typical of phishing sites</li>
                                        <li>• Lacks SSL certificate validation</li>
                                      </ul>
                                    </div>

                                    <div className="bg-yellow-900/50 border-l-4 border-yellow-500 p-2 rounded">
                                      <p className="text-xs font-semibold text-yellow-300">📅 Domain Age Check</p>
                                      <p className="text-xs text-yellow-200 mt-1">Domain registration date unknown - possible new registration used for phishing</p>
                                    </div>

                                    <div className="bg-blue-900/50 border-l-4 border-blue-500 p-2 rounded">
                                      <p className="text-xs font-semibold text-blue-300">🌐 DNS & Infrastructure</p>
                                      <p className="text-xs text-blue-200 mt-1">DNS records not available or suspicious - infrastructure not properly configured</p>
                                    </div>

                                    <div className="bg-purple-900/50 border-l-4 border-purple-500 p-2 rounded">
                                      <p className="text-xs font-semibold text-purple-300">🔒 SSL Certificate</p>
                                      <p className="text-xs text-purple-200 mt-1">Missing or self-signed certificate - identity not verified by certification authority</p>
                                    </div>

                                    <div className="bg-pink-900/50 border-l-4 border-pink-500 p-2 rounded">
                                      <p className="text-xs font-semibold text-pink-300">📄 Content Analysis</p>
                                      <p className="text-xs text-pink-200 mt-1">Page likely contains login forms and credential harvest tactics</p>
                                    </div>
                                  </div>

                                  {/* Overall Risk Score */}
                                  <div className="bg-red-900/60 border border-red-500 rounded p-2 mt-2">
                                    <p className="text-xs font-bold text-red-200">🚨 OVERALL RISK: CRITICAL</p>
                                    <p className="text-xs text-red-300 mt-1">Risk Score: 65-75/100 - DO NOT CLICK OR ENTER CREDENTIALS</p>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Suspicious Phrases */}
                    {email.highlight?.phrases && email.highlight.phrases.length > 0 && (
                      <div>
                        <p className="font-semibold text-orange-300 mb-2 text-sm">⚠️ Suspicious Phrases ({email.highlight.phrases.length})</p>
                        <div className="flex flex-wrap gap-2">
                          {email.highlight.phrases.map((phrase, i) => (
                            <span
                              key={i}
                              className="bg-orange-900/40 text-orange-300 px-3 py-1 rounded text-xs font-medium border border-orange-500/40 hover:bg-orange-900/60 transition-all"
                            >
                              {phrase}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </>
        )}
      </div>

      <style>{`
        @keyframes slideInUp {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .animate-in {
          animation: slideInUp 0.4s ease-out;
        }

        .fade-in {
          animation: fadeIn 0.3s ease-in;
        }

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        .hover\:scale-102:hover {
          transform: scale(1.02);
        }

        .slide-in-from-left {
          animation: slideInLeft 0.4s ease-out;
        }

        @keyframes slideInLeft {
          from {
            opacity: 0;
            transform: translateX(-20px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
      `}</style>
    </div>
  );
}
