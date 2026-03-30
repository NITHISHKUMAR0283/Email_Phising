
import { useState, useEffect } from 'react';
import RiskBadge from './RiskBadge';
import { ExclamationTriangleSVG } from './SimpleIcons';
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
  const [selectedFolder, setSelectedFolder] = useState<'INBOX' | 'SPAM'>('INBOX');  // Folder selector

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
    <div className="w-full flex flex-col">
      {/* Animated Background Blobs - Dynamic Moving Background (ParticleBackground in App handles this) */}
      <div className="hidden">
        {/* Main gradient background */}
        <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950/30 to-slate-950"></div>
        
        {/* Animated glowing orbs */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-500/15 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-blue-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute bottom-0 left-1/2 w-72 h-72 bg-purple-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
        <div className="absolute bottom-1/4 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1.5s'}}></div>
        
        {/* Grid overlay for depth */}
        <div className="absolute inset-0 opacity-[0.02]" style={{
          backgroundImage: 'linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(0deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      {/* Main Content - No header, App.tsx handles it */}
      <div className="flex-1 w-full">
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
          <div className="mb-8 space-y-3 bg-gradient-to-r from-slate-800/60 to-slate-800/40 p-6 rounded-2xl border border-cyan-500/30 backdrop-blur-xl shadow-lg shadow-cyan-500/10">
            <div className="flex items-center justify-between">
              <p className="text-cyan-300 font-semibold">🔍 Scanning emails in progress...</p>
              <p className="text-cyan-300 font-semibold">{scanProgress}%</p>
            </div>
            <div className="w-full h-3 bg-slate-700/50 rounded-full overflow-hidden border border-slate-600/30">
              <div 
                className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 rounded-full transition-all duration-300 shadow-lg shadow-cyan-500/50"
                style={{ width: `${scanProgress}%` }}
              ></div>
            </div>
            <p className="text-slate-400 text-sm">Fetched: {allEmails.length} emails so far...</p>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="bg-gradient-to-r from-red-900/40 to-red-800/30 border border-red-500/50 text-red-200 px-6 py-4 rounded-2xl mb-6 backdrop-blur-xl animate-pulse shadow-lg shadow-red-500/20">
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
                className={`relative group cursor-pointer rounded-2xl overflow-hidden transition-all duration-300 transform hover:scale-105 ${selectedRiskFilter === 'LOW' ? 'border-2 border-green-400 ring-2 ring-green-500/50 shadow-lg shadow-green-500/20' : 'border border-green-500/30 hover:border-green-400/60'}`}
                style={{minHeight: '300px'}}>
                {/* Particle Background Layer */}
                <div className="absolute inset-0 z-0 pointer-events-none opacity-30 bg-gradient-to-br from-green-900/60 to-green-800/40">
                  {[...Array(6)].map((_, i) => (
                    <div
                      key={i}
                      className="absolute rounded-full mix-blend-screen"
                      style={{
                        width: `${30 + i * 15}px`,
                        height: `${30 + i * 15}px`,
                        background: `radial-gradient(circle, rgba(16,185,129,0.6), transparent)`,
                        left: `${10 + i * 15}%`,
                        top: `${20 + (i % 3) * 30}%`,
                        animation: `float-particle ${3 + i * 0.5}s infinite ease-in-out`,
                        animationDelay: `${i * 0.2}s`,
                      }}
                    />
                  ))}
                </div>
                {/* Content Layer */}
                <div className="relative z-10 h-full backdrop-blur-sm bg-gradient-to-br from-green-900/40 to-green-800/30 flex flex-col justify-center items-center p-8">
                  <p className="text-green-300 text-lg font-semibold mb-6">✅ Safe</p>
                  <div className="h-32 mb-6 flex items-center justify-center">
                    <img 
                      src="/google-gmail-svgrepo-com.svg" 
                      alt="Safe" 
                      style={{height: '100px', filter: 'drop-shadow(0 0 20px rgba(16,185,129,0.8))'}}
                    />
                  </div>
                  <p className="text-6xl font-black text-green-300 drop-shadow-lg">{lowRiskCount}</p>
                </div>
              </div>

              {/* Risky Emails - Spam Icon */}
              <div 
                onClick={() => setSelectedRiskFilter('HIGH_MEDIUM')}
                className={`relative group cursor-pointer rounded-2xl overflow-hidden transition-all duration-300 transform hover:scale-105 ${selectedRiskFilter === 'HIGH_MEDIUM' ? 'border-2 border-red-400 ring-2 ring-red-500/50 shadow-lg shadow-red-500/20' : 'border border-red-500/30 hover:border-red-400/60'}`}
                style={{minHeight: '300px'}}>
                {/* Particle Background Layer */}
                <div className="absolute inset-0 z-0 pointer-events-none opacity-30 bg-gradient-to-br from-red-900/60 to-red-800/40">
                  {[...Array(6)].map((_, i) => (
                    <div
                      key={i}
                      className="absolute rounded-full mix-blend-screen"
                      style={{
                        width: `${30 + i * 15}px`,
                        height: `${30 + i * 15}px`,
                        background: `radial-gradient(circle, rgba(239,68,68,0.6), transparent)`,
                        right: `${10 + i * 15}%`,
                        bottom: `${20 + (i % 3) * 30}%`,
                        animation: `float-particle ${3 + i * 0.5}s infinite ease-in-out`,
                        animationDelay: `${i * 0.2}s`,
                      }}
                    />
                  ))}
                </div>
                {/* Content Layer */}
                <div className="relative z-10 h-full backdrop-blur-sm bg-gradient-to-br from-red-900/40 to-red-800/30 flex flex-col justify-center items-center p-8">
                  <p className="text-red-300 text-lg font-semibold mb-6">🚨 Risky</p>
                  <div className="h-32 mb-6 flex items-center justify-center">
                    <img 
                      src="/spam.png" 
                      alt="Risky" 
                      style={{height: '100px', filter: 'drop-shadow(0 0 20px rgba(239,68,68,0.8))'}}
                    />
                  </div>
                  <p className="text-6xl font-black text-red-300 drop-shadow-lg">{highRiskCount + mediumRiskCount}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Performance Metrics */}
        {timing.total_time_ms > 0 && (
          <div className="bg-gradient-to-r from-slate-800/60 via-slate-800/50 to-slate-800/60 border border-slate-600/50 rounded-2xl p-8 mb-8 backdrop-blur-xl shadow-xl hover:shadow-2xl transition-all duration-300">
            <h2 className="text-lg font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-6">
              ⏱️ Performance Metrics
            </h2>
            <div className="grid grid-cols-3 gap-4">
              <div className="bg-gradient-to-br from-blue-900/40 to-blue-800/20 rounded-xl p-4 border border-blue-500/30 hover:border-blue-400 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/20">
                <p className="text-blue-300 text-sm font-medium mb-2">Total Scan Time</p>
                <p className="text-3xl font-bold text-blue-400">
                  {(timing.total_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
              <div className="bg-gradient-to-br from-emerald-900/40 to-emerald-800/20 rounded-xl p-4 border border-emerald-500/30 hover:border-emerald-400 transition-all duration-300 hover:shadow-lg hover:shadow-emerald-500/20">
                <p className="text-emerald-300 text-sm font-medium mb-2">Total Fetch Time</p>
                <p className="text-3xl font-bold text-emerald-400">
                  {(timing.fetch_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
              <div className="bg-gradient-to-br from-purple-900/40 to-purple-800/20 rounded-xl p-4 border border-purple-500/30 hover:border-purple-400 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/20">
                <p className="text-purple-300 text-sm font-medium mb-2">Total Analysis Time</p>
                <p className="text-3xl font-bold text-purple-400">
                  {(timing.total_model_time_ms / 1000).toFixed(2)}s
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex gap-4 mb-8 flex-wrap">
          <button
            onClick={fetchEmails}
            disabled={loading}
            className="px-6 py-3 bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-600 hover:to-cyan-600 disabled:from-emerald-600 disabled:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-emerald-500/50 border border-emerald-400/30"
          >
            {loading ? '⏳ Scanning...' : '🔄 Scan Emails'}
          </button>
          
          {/* Folder Selector */}
          <div className="flex gap-2 ml-auto">
            <button
              onClick={() => { setSelectedFolder('INBOX'); setAllEmails([]); }}
              className={`px-4 py-3 rounded-lg font-semibold transition-all duration-300 backdrop-blur-sm ${
                selectedFolder === 'INBOX'
                  ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white border-2 border-blue-400 shadow-lg shadow-blue-500/50'
                  : 'bg-slate-800/50 text-slate-300 border-2 border-slate-600 hover:border-blue-400 hover:bg-slate-800/70'
              }`}
            >
              📧 Inbox
            </button>
            <button
              onClick={() => { setSelectedFolder('SPAM'); setAllEmails([]); }}
              className={`px-4 py-3 rounded-lg font-semibold transition-all duration-300 backdrop-blur-sm ${
                selectedFolder === 'SPAM'
                  ? 'bg-gradient-to-r from-red-600 to-red-500 text-white border-2 border-red-400 shadow-lg shadow-red-500/50'
                  : 'bg-slate-800/50 text-slate-300 border-2 border-slate-600 hover:border-red-400 hover:bg-slate-800/70'
              }`}
            >
              🚫 Spam
            </button>
          </div>
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
                  className={`relative group border rounded-xl overflow-hidden transition-all duration-300 transform hover:scale-105 cursor-pointer animate-in fade-in slide-in-from-left ${
                    getRiskCategory(email.final_score) === 'HIGH'
                      ? 'border-red-500/40 hover:border-red-400'
                      : getRiskCategory(email.final_score) === 'MEDIUM'
                      ? 'border-yellow-500/40 hover:border-yellow-400'
                      : 'border-green-500/40 hover:border-green-400'
                  } shadow-md hover:shadow-2xl`}
                  style={{
                    animation: `slideInUp 0.4s ease-out ${idx * 0.05}s both`
                  }}>
                  {/* Particle Background Layer */}
                  <div className="absolute inset-0 z-0 pointer-events-none opacity-25">
                    {[...Array(4)].map((_, i) => (
                      <div
                        key={i}
                        className="absolute rounded-full mix-blend-screen"
                        style={{
                          width: `${20 + i * 10}px`,
                          height: `${20 + i * 10}px`,
                          background: 
                            getRiskCategory(email.final_score) === 'HIGH'
                              ? `radial-gradient(circle, rgba(239,68,68,0.5), transparent)`
                              : getRiskCategory(email.final_score) === 'MEDIUM'
                              ? `radial-gradient(circle, rgba(217,119,6,0.5), transparent)`
                              : `radial-gradient(circle, rgba(16,185,129,0.5), transparent)`,
                          left: `${15 + i * 20}%`,
                          top: `${15 + (i % 2) * 60}%`,
                          animation: `float-particle ${2 + i * 0.3}s infinite ease-in-out`,
                          animationDelay: `${i * 0.15}s`,
                        }}
                      />
                    ))}
                  </div>
                  {/* Content Layer */}
                  <div className="relative z-10 backdrop-blur-sm bg-gradient-to-br p-6"
                    style={{
                      background: 
                        getRiskCategory(email.final_score) === 'HIGH'
                          ? 'linear-gradient(to bottom right, rgba(127,29,29,0.4), rgba(120,53,15,0.2))'
                          : getRiskCategory(email.final_score) === 'MEDIUM'
                          ? 'linear-gradient(to bottom right, rgba(113,63,18,0.4), rgba(120,53,15,0.2))'
                          : 'linear-gradient(to bottom right, rgba(20,83,45,0.4), rgba(6,78,59,0.2))'
                    }}>
                    {/* Risk Badge */}
                    <div className="flex items-start justify-between gap-3 mb-3">
                      <div className="flex items-center gap-2 flex-1 min-w-0">
                        {getRiskCategory(email.final_score) === 'HIGH' && <ExclamationTriangleSVG />}
                        <h3 className="font-bold text-white break-words line-clamp-2 hover:text-cyan-300 transition-colors drop-shadow-md">
                          {email.subject}
                        </h3>
                      </div>
                      <div className="flex-shrink-0">
                        <RiskBadge risk={getRiskCategory(email.final_score)} />
                      </div>
                    </div>

                    {/* Sender */}
                    <p className="text-xs text-slate-300 truncate mb-4 font-medium drop-shadow-sm">
                      <span className="font-semibold text-slate-200">From:</span> {email.sender}
                    </p>

                    {/* Quick Info */}
                    <div className="space-y-2 mb-4">
                      <div className="bg-slate-800/60 rounded p-2 border border-slate-600/50 backdrop-blur-sm">
                        <p className="text-xs text-slate-300 font-semibold uppercase tracking-wide">Risk Score</p>
                        <p className={`text-lg font-black drop-shadow-md ${
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
                      <div className="mb-3 p-2 bg-red-900/40 border border-red-500/40 rounded text-xs backdrop-blur-sm">
                        <p className="text-red-300 font-semibold drop-shadow-sm">🔗 {email.highlight?.urls?.length} suspicious URL(s)</p>
                      </div>
                    )}
                    
                    {(email.highlight?.phrases?.length || 0) > 0 && (
                      <div className="mb-3 p-2 bg-yellow-900/40 border border-yellow-500/40 rounded text-xs backdrop-blur-sm">
                        <p className="text-yellow-300 font-semibold drop-shadow-sm">⚠️ {email.highlight?.phrases?.length} suspicious phrase(s)</p>
                      </div>
                    )}

                    {/* Click to View */}
                    <div className="text-center pt-3 border-t border-slate-600/30">
                      <p className="text-xs text-cyan-300 font-semibold hover:text-cyan-200 drop-shadow-md">
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

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes float-particle {
          0%, 100% {
            transform: translate(0, 0);
            opacity: 0.3;
          }
          25% {
            transform: translate(10px, -15px);
            opacity: 0.6;
          }
          50% {
            transform: translate(-5px, -30px);
            opacity: 0.4;
          }
          75% {
            transform: translate(15px, -10px);
            opacity: 0.5;
          }
        }

        @keyframes glow-pulse {
          0%, 100% {
            box-shadow: 0 0 20px rgba(0, 217, 255, 0.3);
          }
          50% {
            box-shadow: 0 0 40px rgba(0, 217, 255, 0.6);
          }
        }

        .animate-in {
          animation: slideInUp 0.4s ease-out;
        }

        .fade-in {
          animation: fadeIn 0.3s ease-in;
        }

        .hover\:scale-102:hover {
          transform: scale(1.02);
        }

        /* Particle effect container enhancement */
        .particle-container {
          position: relative;
          overflow: hidden;
        }

        .particle-bg {
          pointer-events: none;
          position: absolute;
          inset: 0;
          z-index: 0;
          mix-blend-mode: screen;
        }

        .particle {
          position: absolute;
          border-radius: 50%;
          mix-blend-mode: screen;
          filter: blur(1px);
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
