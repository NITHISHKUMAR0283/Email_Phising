
import React, { useState, useEffect } from 'react';
import axios from 'axios';
import RiskBadge from './RiskBadge';
import ScoreBreakdown from './ScoreBreakdown';
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
  components?: {
    url_score: number;
    domain_score: number;
    intent_score: number;
    text_score: number;
    header_score?: number;
    vt_score?: number;
  };
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
  const [selectedFolder, setSelectedFolder] = useState<'INBOX' | 'SPAM'>('INBOX');  // Folder selector

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
        ? `http://localhost:8000/fetch-emails-stream?max_results=10&token=${encodeURIComponent(token)}&folder=${selectedFolder}`
        : `http://localhost:8000/fetch-emails-stream?max_results=10&folder=${selectedFolder}`;
      
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
    <div className="min-h-screen bg-zinc-950 flex flex-col">

      {/* Main Content - No header, App.tsx handles it */}
      <div className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {/* Not Authenticated Screen */}
        {checkingAuth ? (
          <div className="text-center py-16">
            <div className="inline-block">
              <div className="w-12 h-12 rounded-full border-4 border-zinc-700 border-t-red-600 animate-spin mb-4"></div>
              <p className="text-white text-lg font-semibold">Checking authentication...</p>
            </div>
          </div>
        ) : !isAuthenticated ? (
          <div className="text-center py-16">
            <div className="inline-block max-w-md">
              <div className="mb-6">
                <p className="text-5xl mb-4">🔐</p>
              </div>
              <h2 className="text-3xl font-bold text-white mb-4">Sign In Required</h2>
              <p className="text-zinc-400 text-lg mb-8">
                Please sign in with Google to access your email inbox and scan for phishing threats.
              </p>
              <button
                onClick={() => window.location.href = 'http://localhost:8000/login'}
                className="px-8 py-4 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-all duration-300 transform hover:scale-105 hover:-translate-y-1 shadow-lg border border-red-500/50 text-lg"
                style={{boxShadow: '0 0 20px rgba(220, 38, 38, 0.5)'}}
              >
                🔑 Sign In with Google
              </button>
            </div>
          </div>
        ) : (
          <>
          {loading && allEmails.length < 20 && (
          <div className="mb-8 space-y-3 bg-zinc-900/80 p-6 rounded-lg border border-zinc-800 backdrop-blur-sm relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/10 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
            <div className="relative z-10">
              <div className="flex items-center justify-between">
                <p className="text-white font-semibold">Scanning emails in progress...</p>
                <p className="text-red-500 font-semibold">{scanProgress}%</p>
              </div>
              <div className="w-full h-2 bg-zinc-950 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-red-600 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%`, boxShadow: '0 0 10px rgba(220, 38, 38, 0.8)' }}
                ></div>
              </div>
              <p className="text-zinc-500 text-sm">Fetched: {allEmails.length} emails so far...</p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-red-900/50 border border-red-500 text-red-200 px-6 py-4 rounded-lg mb-6 backdrop-blur-sm animate-pulse relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/20 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
            <span className="relative z-10 font-bold mr-2">Alert:</span>
            <span className="relative z-10">{error}</span>
          </div>
        )}

        {/* Stats Cards - 2 Categories: Safe and Risky */}
        {allEmails.length > 0 && (
          <div className="mb-8">
            <div className="grid grid-cols-2 gap-6">
              {/* Safe Emails Card */}
              <div 
                onClick={() => setSelectedRiskFilter('LOW')}
                className={`cursor-pointer bg-zinc-900/80 border border-zinc-800 rounded-lg p-8 backdrop-blur-sm transition-all duration-500 transform hover:-translate-y-1 hover:border-emerald-500/50 hover:shadow-[0_0_20px_rgba(16,185,129,0.2)] relative overflow-hidden group ${selectedRiskFilter === 'LOW' ? 'border-emerald-500/50 shadow-[0_0_20px_rgba(16,185,129,0.2)]' : ''}`}
                style={{minHeight: '250px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'}}>
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-emerald-600/10 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                <div className="relative z-10">
                  <p className="text-xs uppercase tracking-widest text-zinc-500 font-semibold mb-4">Safe Emails</p>
                  <div className="h-24 mb-6 flex items-center justify-center">
                    <img 
                      src="/google-gmail-svgrepo-com.svg" 
                      alt="Safe" 
                      style={{height: '80px'}}
                    />
                  </div>
                  <p className="text-5xl font-bold text-white text-center">{lowRiskCount}</p>
                </div>
              </div>

              {/* Risky Emails Card */}
              <div 
                onClick={() => setSelectedRiskFilter('HIGH_MEDIUM')}
                className={`cursor-pointer bg-zinc-900/80 border border-zinc-800 rounded-lg p-8 backdrop-blur-sm transition-all duration-500 transform hover:-translate-y-1 hover:border-red-500/50 hover:shadow-[0_0_20px_rgba(239,68,68,0.2)] relative overflow-hidden group ${selectedRiskFilter === 'HIGH_MEDIUM' ? 'border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.2)]' : ''}`}
                style={{minHeight: '250px', display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center'}}
              >
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/10 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                <div className="relative z-10">
                  <p className="text-xs uppercase tracking-widest text-zinc-500 font-semibold mb-4">Risky Emails</p>
                  <div className="h-24 mb-6 flex items-center justify-center">
                    <img 
                      src="/spam.png" 
                      alt="Risky" 
                      style={{height: '80px'}}
                    />
                  </div>
                  <p className="text-5xl font-bold text-center" style={{color: '#ef4444', textShadow: '0 0 10px rgba(239, 68, 68, 0.5)'}}>{highRiskCount + mediumRiskCount}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Performance Metrics */}
        {timing.total_time_ms > 0 && (
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-lg p-6 mb-8 backdrop-blur-sm hover:border-red-500/50 hover:shadow-[0_0_20px_rgba(239,68,68,0.2)] transition-all duration-500 relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/10 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
            <div className="relative z-10">
              <h2 className="text-xs uppercase tracking-widest font-bold text-zinc-400 mb-4">
                Performance Metrics
              </h2>
              <div className="flex gap-4 w-full">
                <div className="flex-1 bg-zinc-950/50 rounded-lg p-4 border border-zinc-800 hover:border-zinc-700 transition-all duration-300 relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/5 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                  <div className="relative z-10">
                    <p className="text-zinc-500 text-xs uppercase tracking-widest font-medium mb-2">Scan Time</p>
                    <p className="text-2xl font-bold text-white">
                      {(timing.total_time_ms / 1000).toFixed(2)}s
                    </p>
                  </div>
                </div>
                <div className="flex-1 bg-zinc-950/50 rounded-lg p-4 border border-zinc-800 hover:border-zinc-700 transition-all duration-300 relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/5 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                  <div className="relative z-10">
                    <p className="text-zinc-500 text-xs uppercase tracking-widest font-medium mb-2">Fetch Time</p>
                    <p className="text-2xl font-bold text-white">
                      {(timing.fetch_time_ms / 1000).toFixed(2)}s
                    </p>
                  </div>
                </div>
                <div className="flex-1 bg-zinc-950/50 rounded-lg p-4 border border-zinc-800 hover:border-zinc-700 transition-all duration-300 relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/5 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                  <div className="relative z-10">
                    <p className="text-zinc-500 text-xs uppercase tracking-widest font-medium mb-2">Analysis Time</p>
                    <p className="text-2xl font-bold text-white">
                      {(timing.total_model_time_ms / 1000).toFixed(2)}s
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-4 mb-8 flex-wrap">
          <button
            onClick={fetchEmails}
            disabled={loading}
            className={`px-6 py-3 rounded-lg font-semibold transition-all duration-300 border border-zinc-800 ${
              loading 
                ? 'bg-zinc-900 text-zinc-500 cursor-not-allowed'
                : 'bg-red-600 text-white hover:bg-red-700 transform hover:-translate-y-1 shadow-lg'
            }`}
            style={!loading ? {boxShadow: '0 0 15px rgba(220, 38, 38, 0.4)'} : {}}
          >
            {loading ? 'Scanning...' : 'Scan Emails'}
          </button>
          
          {/* Folder Selector */}
          <div className="flex gap-2 ml-auto">
            <button
              onClick={() => { setSelectedFolder('INBOX'); setAllEmails([]); }}
              className={`px-4 py-3 rounded-lg font-semibold transition-all duration-300 border ${
                selectedFolder === 'INBOX'
                  ? 'bg-red-950/30 text-red-500 border-red-900/50 shadow-[0_0_10px_rgba(220,38,38,0.1)]'
                  : 'bg-zinc-900 text-zinc-500 border-zinc-800 hover:text-zinc-300'
              }`}
            >
              Inbox
            </button>
            <button
              onClick={() => { setSelectedFolder('SPAM'); setAllEmails([]); }}
              className={`px-4 py-3 rounded-lg font-semibold transition-all duration-300 border ${
                selectedFolder === 'SPAM'
                  ? 'bg-red-950/30 text-red-500 border-red-900/50 shadow-[0_0_10px_rgba(220,38,38,0.1)]'
                  : 'bg-zinc-900 text-zinc-500 border-zinc-800 hover:text-zinc-300'
              }`}
            >
              Spam
            </button>
          </div>
        </div>

        {/* Email List Container */}
        {loading && allEmails.length === 0 ? (
          <div className="text-center py-16">
            <div className="inline-block">
              <div className="w-12 h-12 rounded-full border-4 border-zinc-700 border-t-red-600 animate-spin mb-4"></div>
              <p className="text-white text-lg font-semibold">Scanning your inbox...</p>
              <p className="text-zinc-500 text-sm mt-2">Please ensure you've signed in with Google</p>
            </div>
          </div>
        ) : error && allEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-zinc-400 text-lg mb-4">Unable to load emails</p>
            <button
              onClick={fetchEmails}
              className="px-6 py-2 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-all"
            >
              Try Again
            </button>
          </div>
        ) : allEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-white text-lg">No emails found</p>
          </div>
        ) : filteredEmails.length === 0 ? (
          <div className="text-center py-16">
            <p className="text-zinc-400 text-lg">
              {selectedRiskFilter === 'LOW' 
                ? 'No safe emails found' 
                : 'No risky emails found'}
            </p>
            <button
              onClick={() => setSelectedRiskFilter('NONE')}
              className="mt-4 px-6 py-2 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-all"
            >
              View All Emails
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="text-white text-sm font-semibold mb-4">
              Showing {filteredEmails.length} email{filteredEmails.length !== 1 ? 's' : ''} {selectedRiskFilter === 'LOW' && '(Safe)'} {selectedRiskFilter === 'HIGH_MEDIUM' && '(Risky)'}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredEmails.map((email, idx) => (
                <div
                  key={`${email.id}-${idx}`}
                  onClick={() => onEmailSelect?.(email)}
                  className="border border-zinc-800 rounded-lg backdrop-blur-sm transition-all duration-300 transform hover:-translate-y-1 cursor-pointer animate-in fade-in slide-in-from-left p-6 bg-zinc-900/60 hover:border-red-500/50 hover:shadow-[0_0_20px_rgba(239,68,68,0.2)] shadow-md flex flex-col h-full relative overflow-hidden group"
                  style={{
                    animation: `slideInUp 0.4s ease-out ${idx * 0.05}s both`
                  }}
                >
                  {/* Shimmer Wave Effect */}
                  <div className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/10 to-transparent" style={{animation: '3s ease 0s infinite normal none running shimmer'}}></div>
                  
                  {/* Content Wrapper */}
                  <div className="relative z-10">
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
                    <p className="text-xs text-zinc-500 truncate mb-4">
                      <span className="font-semibold text-zinc-400">From:</span> {email.sender}
                    </p>

                    {/* Quick Info */}
                    <div className="space-y-2 mb-4">
                      <div className="bg-zinc-800/60 rounded p-2 border border-zinc-700">
                        <p className="text-xs text-zinc-500 font-semibold uppercase">Risk Score</p>
                        <p className={`text-lg font-bold ${
                          getRiskCategory(email.final_score) === 'HIGH' ? 'text-red-500' :
                          getRiskCategory(email.final_score) === 'MEDIUM' ? 'text-orange-400' :
                          'text-white'
                        }`}>
                          {(email.final_score * 100).toFixed(0)}%
                        </p>
                      </div>
                    </div>

                    {/* Suspicious Info - Inline Alerts */}
                    {(email.highlight?.urls?.length || 0) > 0 && (
                      <div className="mb-2 px-3 py-2 bg-red-950/40 border border-red-900/50 rounded-md flex items-center gap-2 text-xs">
                        <span className="text-red-400 font-semibold">Link:</span>
                        <span className="text-red-300">{email.highlight?.urls?.length} suspicious URL{(email.highlight?.urls?.length || 0) !== 1 ? 's' : ''}</span>
                      </div>
                    )}
                    
                    {(email.highlight?.phrases?.length || 0) > 0 && (
                      <div className="mb-2 px-3 py-2 bg-red-950/40 border border-red-900/50 rounded-md flex items-center gap-2 text-xs">
                        <span className="text-orange-400 font-semibold">Warning:</span>
                        <span className="text-orange-300">{email.highlight?.phrases?.length} suspicious phrase{(email.highlight?.phrases?.length || 0) !== 1 ? 's' : ''}</span>
                      </div>
                    )}
                  </div>

                  {/* Score Breakdown Speedometer - with mt-auto to push to bottom */}
                  <div className="mt-auto pt-4 relative z-10">
                    <ScoreBreakdown components={email.components} final_score={email.final_score} />
                    
                    {/* Click to View */}
                    <div className="flex items-end pt-3 border-t border-zinc-700/30 mt-3">
                      <p className="text-xs text-zinc-400 font-medium hover:text-white transition-colors w-full text-right">
                        Click to view details →
                      </p>
                    </div>
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

        @keyframes shimmer {
          0% {
            transform: translateX(-100%);
          }
          100% {
            transform: translateX(100%);
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
