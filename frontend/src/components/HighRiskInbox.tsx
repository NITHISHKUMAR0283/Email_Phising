
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
  groq_time_ms?: number;
  highlight?: { urls: string[]; phrases: string[] };
  ai_analysis?: any;
  groq_domain?: string;
  groq_is_valid_domain?: boolean;
  groq_highlighted_text?: string[];
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

interface HighRiskInboxProps {
  onEmailSelect?: (email: EmailData) => void;
  cachedEmails?: EmailData[];
  setCachedEmails?: (emails: EmailData[]) => void;
}

export default function HighRiskInbox({ onEmailSelect, cachedEmails = [], setCachedEmails }: HighRiskInboxProps) {
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

  // Check if user is authenticated on component mount and load emails or use cache
  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        // Get token from localStorage
        const token = localStorage.getItem('gmail_access_token');
        
        const fetchOptions: RequestInit = token 
          ? { headers: { 'Authorization': `Bearer ${token}` } }
          : {};
        
        const response = await fetch('http://localhost:8000/check-auth', fetchOptions);
        if (response.ok) {
          setIsAuthenticated(true);
          setCheckingAuth(false);
          // Check cache first - if populated, use it
          if (cachedEmails && cachedEmails.length > 0) {
            console.log('✓ Using cached emails:', cachedEmails.length);
            setAllEmails(cachedEmails);
          } else {
            // Cache is empty, fetch fresh emails
            console.log('📧 Cache empty, fetching fresh emails...');
            fetchEmails();
          }
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
    
    let collectedEmails: EmailData[] = [];  // Track emails locally for caching
    let expectedTotal = 10;  // Default expected total
    
    try {
      // Get token from localStorage or use empty string (backend will check session)
      const token = localStorage.getItem('gmail_access_token') || '';
      const url = token 
        ? `http://localhost:8000/fetch-emails-stream?max_results=10&token=${encodeURIComponent(token)}`
        : 'http://localhost:8000/fetch-emails-stream?max_results=10';
      
      const eventSource = new EventSource(url);

      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data);

        if (data.type === 'init') {
          expectedTotal = data.total_to_fetch || 10;
          console.log('Starting email scan...', `Expecting ${expectedTotal} emails`);
          setScanProgress(5);
        } else if (data.type === 'email') {
          const newEmail = data.email;
          collectedEmails.push(newEmail);  // Add to local collection
          setAllEmails((prev) => [...prev, newEmail]);
          // Calculate progress proportionally: 5% start + 90% for data collection
          const progress = Math.min(5 + ((data.count / expectedTotal) * 90), 95);
          setScanProgress(progress);
        } else if (data.type === 'complete') {
          setTiming({
            fetch_time_ms: data.fetch_time_ms,
            total_model_time_ms: data.total_model_time_ms,
            total_time_ms: (data.fetch_time_ms + data.total_model_time_ms),
          });
          setScanProgress(100);
          setLoading(false);
          eventSource.close();
          
          // Cache all collected emails in parent component
          if (setCachedEmails && collectedEmails.length > 0) {
            setCachedEmails(collectedEmails);
            console.log('✓ Emails cached in parent:', collectedEmails.length);
          }
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

  // Helper function to get risk category from final_score (NEW: using combined score)
  const getRiskCategory = (finalScore: number): 'HIGH' | 'MEDIUM' | 'LOW' => {
    if (finalScore >= 0.75) return 'HIGH';     // HIGH: 75%+
    if (finalScore >= 0.60) return 'MEDIUM';   // MEDIUM: 60-75%
    return 'LOW';                               // LOW: < 60%
  };

  const highRiskCount = allEmails.filter(e => getRiskCategory(e.final_score) === 'HIGH').length;
  const mediumRiskCount = allEmails.filter(e => getRiskCategory(e.final_score) === 'MEDIUM').length;
  const lowRiskCount = allEmails.filter(e => getRiskCategory(e.final_score) === 'LOW').length;

  // Filter emails based on selected risk level (using final_score, not old risk_score)
  const filteredEmails = selectedRiskFilter === 'NONE' 
    ? allEmails 
    : selectedRiskFilter === 'LOW'
    ? allEmails.filter(e => getRiskCategory(e.final_score) === 'LOW')
    : allEmails.filter(e => getRiskCategory(e.final_score) === 'HIGH' || getRiskCategory(e.final_score) === 'MEDIUM');

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
              Showing {filteredEmails.length} email{filteredEmails.length !== 1 ? 's' : ''} {selectedRiskFilter === 'LOW' && '(Safe)'} {selectedRiskFilter === 'HIGH_MEDIUM' && '(Risky)'}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredEmails.map((email, idx) => (
                <div
                  key={`${email.id}-${idx}`}
                  onClick={() => onEmailSelect?.(email)}
                  className={`border rounded-xl backdrop-blur-sm transition-all duration-300 transform hover:scale-105 cursor-pointer animate-in fade-in slide-in-from-left p-6 ${
                    getRiskCategory(email.final_score) === 'HIGH'
                      ? 'bg-gradient-to-br from-red-900/30 to-red-800/20 border-red-500/40 hover:border-red-400 hover:from-red-900/50 hover:to-red-800/40 hover:shadow-lg hover:shadow-red-500/30'
                      : getRiskCategory(email.final_score) === 'MEDIUM'
                      ? 'bg-gradient-to-br from-yellow-900/30 to-yellow-800/20 border-yellow-500/40 hover:border-yellow-400 hover:from-yellow-900/50 hover:to-yellow-800/40 hover:shadow-lg hover:shadow-yellow-500/30'
                      : 'bg-gradient-to-br from-green-900/30 to-green-800/20 border-green-500/40 hover:border-green-400 hover:from-green-900/50 hover:to-green-800/40 hover:shadow-lg hover:shadow-green-500/30'
                  } shadow-md hover:shadow-2xl`}
                  style={{
                    animation: `slideInUp 0.4s ease-out ${idx * 0.05}s both`
                  }}
                >
                  {/* Risk Badge */}
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      {getRiskCategory(email.final_score) === 'HIGH' && <ExclamationTriangleSVG />}
                      <h3 className="font-bold text-white break-words line-clamp-2 hover:text-blue-300 transition-colors">
                        {email.subject}
                      </h3>
                    </div>
                    <div className="flex-shrink-0">
                      <RiskBadge risk={getRiskCategory(email.final_score)} />
                    </div>
                  </div>

                  {/* Sender */}
                  <p className="text-xs text-slate-400 truncate mb-4">
                    <span className="font-semibold text-slate-300">From:</span> {email.sender}
                  </p>

                  {/* Quick Info */}
                  <div className="space-y-2 mb-4">
                    <div className="bg-slate-800/50 rounded p-2 border border-slate-700/50">
                      <p className="text-xs text-slate-400 font-semibold uppercase">Risk Score</p>
                      <p className={`text-lg font-bold ${
                        getRiskCategory(email.final_score) === 'HIGH' ? 'text-red-400' :
                        getRiskCategory(email.final_score) === 'MEDIUM' ? 'text-yellow-400' :
                        'text-green-400'
                      }`}>
                        {(email.final_score * 100).toFixed(0)}%
                      </p>
                    </div>
                  </div>

                  {/* Suspicious Info */}
                  {(email.highlight?.urls?.length || 0) > 0 && (
                    <div className="mb-3 p-2 bg-red-900/30 border border-red-500/30 rounded text-xs">
                      <p className="text-red-300 font-semibold">🔗 {email.highlight?.urls?.length} suspicious URL(s)</p>
                    </div>
                  )}
                  
                  {(email.highlight?.phrases?.length || 0) > 0 && (
                    <div className="mb-3 p-2 bg-yellow-900/30 border border-yellow-500/30 rounded text-xs">
                      <p className="text-yellow-300 font-semibold">⚠️ {email.highlight?.phrases?.length} suspicious phrase(s)</p>
                    </div>
                  )}

                  {/* Click to View */}
                  <div className="text-center pt-3 border-t border-slate-600/30">
                    <p className="text-xs text-blue-300 font-medium hover:text-blue-200">
                      Click to view details →
                    </p>
                  </div>
                </div>
              ))}
            </div>
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
