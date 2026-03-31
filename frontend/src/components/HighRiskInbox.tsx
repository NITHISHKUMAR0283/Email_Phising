
import { useState, useEffect } from 'react';
import { checkAuth } from '../api';

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
  const [scanProgress, setScanProgress] = useState(0);
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<'LOW' | 'HIGH_MEDIUM' | 'NONE'>('NONE');
  const [selectedFolder, setSelectedFolder] = useState<'INBOX' | 'SPAM'>('INBOX');

  // Check if user is authenticated on component mount and load emails or use cache
  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        // Get token from localStorage
        const token = localStorage.getItem('gmail_access_token');
        
        const isAuth = await checkAuth(token || undefined);
        if (isAuth) {
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
    <div className="w-full flex flex-col gap-6 px-6 py-6">
      {/* Main Content */}
      <div className="flex-1 w-full">
        {/* Not Authenticated Screen */}
        {checkingAuth ? (
          <div className="flex items-center justify-center min-h-[200px]">
            <div className="text-center">
              <div className="w-10 h-10 rounded-full border-3 border-cyan-500 border-t-blue-400 animate-spin mx-auto mb-3"></div>
              <p className="text-slate-300 text-sm font-medium">Checking authentication...</p>
            </div>
          </div>
        ) : !isAuthenticated ? (
          <div className="text-center py-12">
            <div className="inline-block max-w-md">
              <p className="text-4xl mb-3">🔐</p>
              <h2 className="text-2xl font-bold text-cyan-300 mb-2">Authentication Required</h2>
              <p className="text-slate-400 text-sm mb-6">
                Sign in with Google to scan your inbox for phishing threats.
              </p>
              <button
                onClick={() => window.location.href = 'http://localhost:8000/login'}
                className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white text-sm font-semibold rounded-lg transition-all duration-300 shadow-lg hover:shadow-cyan-500/50"
              >
                🔑 Sign In with Google
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* SCANNING PROGRESS */}
            {loading && allEmails.length < 20 && (
              <div className="bg-slate-800/40 border border-cyan-500/30 rounded-lg p-4 backdrop-blur-sm mb-6">
                <div className="flex items-center justify-between gap-4 mb-2">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 bg-cyan-400 rounded-full animate-pulse"></div>
                    <p className="text-cyan-300 text-sm font-medium">Scanning emails...</p>
                  </div>
                  <p className="text-cyan-300 text-sm font-bold font-mono">{scanProgress}%</p>
                </div>
                <div className="w-full h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* ERROR MESSAGE */}
            {error && (
              <div className="bg-rose-900/30 border border-rose-500/50 text-rose-200 text-sm px-4 py-3 rounded-lg mb-6 backdrop-blur-sm">
                ⚠️ {error}
              </div>
            )}

            {/* KPI METRICS ROW - Compact & Sleek */}
            {allEmails.length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                {/* Safe Emails */}
                <div 
                  onClick={() => setSelectedRiskFilter('LOW')}
                  className={`px-4 py-3 rounded-lg border transition-all duration-300 cursor-pointer backdrop-blur-sm ${
                    selectedRiskFilter === 'LOW'
                      ? 'bg-emerald-900/40 border-emerald-500 ring-1 ring-emerald-500/50'
                      : 'bg-slate-800/40 border-slate-700 hover:bg-slate-800/60 hover:border-emerald-500/50'
                  }`}
                >
                  <p className="text-slate-400 text-xs font-semibold uppercase tracking-wide mb-1">Safe</p>
                  <p className="text-emerald-400 text-2xl font-bold font-mono">{lowRiskCount}</p>
                </div>

                {/* Risky Emails */}
                <div 
                  onClick={() => setSelectedRiskFilter('HIGH_MEDIUM')}
                  className={`px-4 py-3 rounded-lg border transition-all duration-300 cursor-pointer backdrop-blur-sm ${
                    selectedRiskFilter === 'HIGH_MEDIUM'
                      ? 'bg-rose-900/40 border-rose-500 ring-1 ring-rose-500/50'
                      : 'bg-slate-800/40 border-slate-700 hover:bg-slate-800/60 hover:border-rose-500/50'
                  }`}
                >
                  <p className="text-slate-400 text-xs font-semibold uppercase tracking-wide mb-1">Risky</p>
                  <p className="text-rose-400 text-2xl font-bold font-mono">{highRiskCount + mediumRiskCount}</p>
                </div>

                {/* Total Scanned */}
                <div className="px-4 py-3 rounded-lg border bg-slate-800/40 border-slate-700 backdrop-blur-sm">
                  <p className="text-slate-400 text-xs font-semibold uppercase tracking-wide mb-1">Total Scanned</p>
                  <p className="text-slate-200 text-2xl font-bold font-mono">{allEmails.length}</p>
                </div>
              </div>
            )}

            {/* ACTION TOOLBAR */}
            <div className="flex items-center justify-between gap-3 mb-6 flex-wrap">
              <button
                onClick={fetchEmails}
                disabled={loading}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-cyan-700 disabled:opacity-50 text-white text-sm font-semibold rounded-lg transition-all duration-300 disabled:cursor-not-allowed shadow-sm"
              >
                {loading ? '⏳ Scanning...' : '🔄 Scan'}
              </button>
              
              {/* Folder Selector - Toggle Buttons */}
              <div className="flex gap-2 ml-auto">
                <button
                  onClick={() => { setSelectedFolder('INBOX'); setAllEmails([]); }}
                  className={`px-3 py-2 text-sm font-medium rounded-lg transition-all duration-300 ${
                    selectedFolder === 'INBOX'
                      ? 'bg-blue-600 text-white border border-blue-500'
                      : 'bg-slate-800/40 text-slate-300 border border-slate-700 hover:border-blue-500/50'
                  }`}
                >
                  📧 Inbox
                </button>
                <button
                  onClick={() => { setSelectedFolder('SPAM'); setAllEmails([]); }}
                  className={`px-3 py-2 text-sm font-medium rounded-lg transition-all duration-300 ${
                    selectedFolder === 'SPAM'
                      ? 'bg-rose-600 text-white border border-rose-500'
                      : 'bg-slate-800/40 text-slate-300 border border-slate-700 hover:border-rose-500/50'
                  }`}
                >
                  🚫 Spam
                </button>
              </div>
            </div>

            {/* EMAIL DATA TABLE - High Density List View */}
            {loading && allEmails.length === 0 ? (
              <div className="flex items-center justify-center min-h-[300px]">
                <div className="text-center">
                  <div className="w-10 h-10 rounded-full border-3 border-cyan-500 border-t-blue-400 animate-spin mx-auto mb-3"></div>
                  <p className="text-slate-300 text-sm font-medium">Scanning inbox...</p>
                </div>
              </div>
            ) : error && allEmails.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-slate-400 text-sm mb-3">Unable to load emails</p>
                <button
                  onClick={fetchEmails}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-all"
                >
                  Try Again
                </button>
              </div>
            ) : allEmails.length === 0 ? (
              <div className="text-center py-8 text-slate-400 text-sm">
                No emails found
              </div>
            ) : filteredEmails.length === 0 ? (
              <div className="text-center py-8">
                <p className="text-slate-400 text-sm mb-4">
                  {selectedRiskFilter === 'LOW' ? 'No safe emails' : 'No risky emails'}
                </p>
                <button
                  onClick={() => setSelectedRiskFilter('NONE')}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-all"
                >
                  View All
                </button>
              </div>
            ) : (
              <div className="border border-slate-700 rounded-lg overflow-hidden bg-slate-800/30 backdrop-blur-sm">
                {/* Table Header */}
                <div className="grid grid-cols-12 gap-4 px-4 py-3 bg-slate-800/60 border-b border-slate-700 text-xs font-semibold text-slate-400 uppercase tracking-wide">
                  <div className="col-span-5">Subject</div>
                  <div className="col-span-3">Sender</div>
                  <div className="col-span-2">Risk Score</div>
                  <div className="col-span-2">Indicators</div>
                </div>

                {/* Table Body - Email Rows */}
                <div className="divide-y divide-slate-700">
                  {filteredEmails.map((email, idx) => {
                    const riskCat = getRiskCategory(email.final_score);
                    const riskColor = 
                      riskCat === 'HIGH' ? 'text-rose-400' :
                      riskCat === 'MEDIUM' ? 'text-amber-400' :
                      'text-emerald-400';
                    const bgColor =
                      riskCat === 'HIGH' ? 'hover:bg-rose-950/20' :
                      riskCat === 'MEDIUM' ? 'hover:bg-amber-950/20' :
                      'hover:bg-emerald-950/20';

                    return (
                      <div
                        key={`${email.id}-${idx}`}
                        onClick={() => onEmailSelect?.(email)}
                        className={`grid grid-cols-12 gap-4 px-4 py-3 items-center cursor-pointer transition-all duration-300 ${bgColor} border-slate-700/50 group`}
                      >
                        {/* Subject */}
                        <div className="col-span-5 min-w-0 flex items-center gap-2">
                          {riskCat === 'HIGH' && <span className="text-rose-500 flex-shrink-0">⚠️</span>}
                          <div className="min-w-0 flex-1">
                            <p className="text-slate-200 text-sm font-medium truncate group-hover:text-cyan-300 transition-colors">
                              {email.subject}
                            </p>
                          </div>
                        </div>

                        {/* Sender */}
                        <div className="col-span-3 min-w-0">
                          <p className="text-slate-400 text-xs truncate">
                            {email.sender}
                          </p>
                        </div>

                        {/* Risk Score - Mini Progress Bar + Percentage */}
                        <div className="col-span-2 flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all ${
                                riskCat === 'HIGH' ? 'bg-rose-500' :
                                riskCat === 'MEDIUM' ? 'bg-amber-500' :
                                'bg-emerald-500'
                              }`}
                              style={{ width: `${email.final_score * 100}%` }}
                            ></div>
                          </div>
                          <span className={`text-xs font-bold font-mono flex-shrink-0 ${riskColor}`}>
                            {(email.final_score * 100).toFixed(0)}%
                          </span>
                        </div>

                        {/* Warning Indicators */}
                        <div className="col-span-2 flex items-center gap-2">
                          {(email.highlight?.urls?.length ?? 0) > 0 && (
                            <div className="flex items-center gap-1 px-2 py-1 bg-rose-900/30 border border-rose-500/30 rounded text-xs text-rose-300 font-medium">
                              <span>🔗</span>
                              <span>{email.highlight?.urls?.length}</span>
                            </div>
                          )}
                          {(email.highlight?.phrases?.length ?? 0) > 0 && (
                            <div className="flex items-center gap-1 px-2 py-1 bg-amber-900/30 border border-amber-500/30 rounded text-xs text-amber-300 font-medium">
                              <span>⚡</span>
                              <span>{email.highlight?.phrases?.length}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Table Footer - Result Count */}
                <div className="px-4 py-2 bg-slate-800/40 border-t border-slate-700 text-xs text-slate-400">
                  Showing {filteredEmails.length} of {allEmails.length} email{allEmails.length !== 1 ? 's' : ''}
                </div>
              </div>
            )}

            {/* PERFORMANCE METRICS - Compact Footer */}
            {timing.total_time_ms > 0 && (
              <div className="mt-6 grid grid-cols-3 gap-3">
                <div className="px-3 py-2 bg-slate-800/40 border border-slate-700 rounded text-xs">
                  <p className="text-slate-400 mb-1">Scan Time</p>
                  <p className="text-slate-200 font-bold font-mono">{(timing.total_time_ms / 1000).toFixed(2)}s</p>
                </div>
                <div className="px-3 py-2 bg-slate-800/40 border border-slate-700 rounded text-xs">
                  <p className="text-slate-400 mb-1">Fetch</p>
                  <p className="text-slate-200 font-bold font-mono">{(timing.fetch_time_ms / 1000).toFixed(2)}s</p>
                </div>
                <div className="px-3 py-2 bg-slate-800/40 border border-slate-700 rounded text-xs">
                  <p className="text-slate-400 mb-1">Analysis</p>
                  <p className="text-slate-200 font-bold font-mono">{(timing.total_model_time_ms / 1000).toFixed(2)}s</p>
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
            transform: translateY(10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes float-particle {
          0%, 100% {
            transform: translate(0, 0);
            opacity: 0.3;
          }
          50% {
            transform: translate(8px, -12px);
            opacity: 0.6;
          }
        }

        .animate-in {
          animation: slideInUp 0.3s ease-out;
        }

        .fade-in {
          animation: fadeIn 0.2s ease-in;
        }
      `}</style>
    </div>
  );
}
