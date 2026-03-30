
import DetectionForm from './components/DetectionForm';
import EmailList from './components/EmailList';
import EmailDetail from './components/EmailDetail';
import HighRiskInbox from './components/HighRiskInbox';
import EmailDetailPage from './components/EmailDetailPage';
import ParticleBackground from './components/ParticleBackground';
import React, { useState, useEffect } from 'react';

function App() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [tab, setTab] = useState<'gmail' | 'manual'>('gmail');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [selectedEmail, setSelectedEmail] = useState<any>(null);
  const [cachedEmails, setCachedEmails] = useState<any[]>([]); // Cache emails to prevent refetch

  // Check authentication on mount and restore token from localStorage
  useEffect(() => {
    const checkAuth = async () => {
      try {
        // Check for token in URL (from OAuth callback)
        const urlParams = new URLSearchParams(window.location.search);
        const tokenFromUrl = urlParams.get('token');
        
        if (tokenFromUrl) {
          // Save token to localStorage
          localStorage.setItem('gmail_access_token', tokenFromUrl);
          console.log('✓ Token saved to localStorage');
          // Clean up URL
          window.history.replaceState({}, document.title, window.location.pathname);
          setIsAuthenticated(true);
          setCheckingAuth(false);
          return;
        }
        
        // Try to use token from localStorage
        const savedToken = localStorage.getItem('gmail_access_token');
        if (savedToken) {
          console.log('✓ Using saved token from localStorage');
          const response = await fetch('http://localhost:8000/check-auth', {
            headers: {
              'Authorization': `Bearer ${savedToken}`
            }
          });
          setIsAuthenticated(response.ok);
          if (response.ok) {
            setCheckingAuth(false);
            return;
          }
        }
        
        // If no saved token, check backend
        const response = await fetch('http://localhost:8000/check-auth');
        setIsAuthenticated(response.ok);
      } catch (err) {
        setIsAuthenticated(false);
      } finally {
        setCheckingAuth(false);
      }
    };
    checkAuth();
  }, []);

  const handleDetection = (result: any) => {
    setAnalyses(prev => [...prev, result]);
    setSelectedIdx(analyses.length);
  };

  return (
    <div className="min-h-screen bg-black flex flex-col" style={{ background: 'linear-gradient(135deg, #000000 0%, #0a0a0a 50%, #05050a 100%)' }}>
      {/* Animated Dark Red Accent Blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <div className="absolute top-20 left-10 w-72 h-72 bg-red-600/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 right-10 w-72 h-72 bg-red-500/5 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      {/* Subtle Particle Background */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-20">
        <ParticleBackground />
      </div>

      {/* Header Navigation - Dark Gray with Red Accents */}
      <nav 
        className="relative z-20 border-b border-red-600/30 backdrop-blur-sm overflow-hidden" 
        style={{perspective: '1200px'}}
      >
        {/* Dark Gradient Background */}
        <div 
          className="absolute inset-0 opacity-40 pointer-events-none"
          style={{
            background: 'linear-gradient(45deg, #1a1a1a, #2d1a1a, #1a1a1a)',
            backgroundSize: '400% 400%',
            animation: 'gradientShift 8s ease infinite'
          }}
        ></div>

        {/* Red Glow Ray Effect */}
        <div 
          className="absolute inset-0 pointer-events-none overflow-hidden"
          style={{
            background: 'linear-gradient(90deg, transparent, rgba(220,38,38,0.15), transparent)',
            animation: 'lightRay 3s ease-in-out infinite'
          }}
        ></div>

        <div 
          className="w-full px-6 py-4 flex flex-row justify-center bg-gradient-to-b from-slate-900/80 to-slate-950/90 border-t border-red-600/20 transition-all duration-500 relative z-10"
          style={{
            boxShadow: `
              0 20px 60px rgba(0, 0, 0, 0.95),
              inset 0 1px 0 rgba(255, 255, 255, 0.05),
              0 0 30px rgba(220, 38, 38, 0.1)
            `,
            backdropFilter: 'blur(20px)',
          }}
        >
          <div className="max-w-7xl w-full flex flex-row justify-between items-center gap-4">
          {/* LEFT SECTION - Logo and Title */}
          <div className="flex flex-row items-center gap-4 group relative flex-shrink-0">
            {/* Glow Background for Logo - Red */}
            <div 
              className="absolute w-16 h-16 bg-gradient-to-r from-red-600/30 to-red-500/20 rounded-full blur-xl -inset-2 group-hover:from-red-600/50 group-hover:to-red-500/40 transition-all duration-500"
              style={{animation: 'pulseGlow 3s ease-in-out infinite'}}
            ></div>

            {/* Blue-Red Shield Icon */}
            <div 
              className="w-12 h-12 bg-gradient-to-br from-blue-400 via-red-500 to-red-600 rounded-xl flex items-center justify-center transform group-hover:scale-110 transition-all duration-300 shadow-lg relative z-10 flex-shrink-0" 
              style={{
                boxShadow: 'inset -2px -2px 10px rgba(0,0,0,0.5), inset 2px 2px 10px rgba(255,0,0,0.2), 0 0 20px rgba(220,38,38,0.6)',
                animation: 'floatBob 3s ease-in-out infinite'
              }}
            >
              <span className="text-xl" style={{animation: 'spin360 4s linear infinite'}}>🛡️</span>
            </div>

            {/* TEXT BLOCK - Title & Subtitle */}
            <div className="flex flex-col items-start justify-center relative z-10 min-w-0">
              <h1 
                className="text-2xl md:text-3xl font-bold text-white pb-1 whitespace-nowrap"
                style={{
                  animation: 'textGlide 0.8s ease-out',
                  borderBottom: '2px solid #dc2626',
                  display: 'inline-block'
                }}
              >
                PhishGuard AI
              </h1>
              <p 
                className="text-gray-400 text-xs md:text-sm font-medium mt-1 whitespace-nowrap"
                style={{animation: 'fadeUpSlide 0.8s ease-out 0.2s both'}}
              >
                Intelligent Email Threat Detection
              </p>
            </div>
          </div>

          {/* RIGHT SECTION - Auth Status */}
          {!checkingAuth && (
            isAuthenticated ? (
              <div className="flex flex-row items-center gap-3 flex-shrink-0 ml-auto">
                <div className="flex flex-row items-center gap-2 px-4 py-2 bg-red-600/20 border border-red-600/50 rounded-lg min-w-fit" style={{boxShadow: '0 0 15px rgba(220, 38, 38, 0.3)'}}>
                  <div className="w-2 h-2 bg-red-400 rounded-full animate-pulse flex-shrink-0"></div>
                  <span className="text-white font-semibold whitespace-nowrap text-sm">✓ Logged In</span>
                </div>
                <button
                  onClick={() => {
                    setIsAuthenticated(false);
                    localStorage.removeItem('gmail_access_token');
                    window.location.href = 'http://localhost:8000/logout';
                  }}
                  className="px-6 py-3 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-all duration-300 transform hover:scale-105 shadow-lg border border-red-500/50 flex flex-row items-center gap-2 whitespace-nowrap flex-shrink-0"
                  style={{boxShadow: '0 0 20px rgba(220, 38, 38, 0.4)'}}
                >
                  🔒 Logout
                </button>
              </div>
            ) : (
              <button
                onClick={() => window.location.href = 'http://localhost:8000/login'}
                className="px-8 py-3 bg-red-600 text-white rounded-lg font-semibold hover:bg-red-700 transition-all duration-300 transform hover:scale-105 shadow-lg border border-red-500/50 whitespace-nowrap relative overflow-hidden group flex-shrink-0 ml-auto"
                style={{
                  boxShadow: '0 0 20px rgba(220, 38, 38, 0.5)',
                }}
              >
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent"
                  style={{animation: 'waveSlide 2s ease-in-out infinite'}}
                ></div>
                <span className="relative z-10 block">Sign in with Google</span>
              </button>
            )
          )}
          </div>
        </div>

        {/* Tab Navigation with Red Glowing Borders */}
        <div className="border-t border-red-600/20 px-6 py-4 bg-gradient-to-r from-slate-950/60 to-slate-900/60 relative z-10 flex flex-row justify-center">
          <div className="max-w-7xl w-full flex gap-4 justify-center">
            <button
              onClick={() => setTab('gmail')}
              className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 relative overflow-hidden group ${
                tab === 'gmail'
                  ? 'bg-slate-800/80 text-white border-2 border-red-600'
                  : 'bg-slate-800/30 text-gray-300 hover:bg-slate-800/50 border border-slate-700/50 hover:border-red-600/50'
              }`}
              style={{
                boxShadow: tab === 'gmail' ? '0 0 20px rgba(220, 38, 38, 0.5), inset 0 1px 0 rgba(255,255,255,0.05)' : 'inset 0 1px 0 rgba(255,255,255,0.02)',
              }}
            >
              {tab === 'gmail' && (
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/20 to-transparent" 
                  style={{animation: 'shimmer 3s infinite'}}
                ></div>
              )}
              <span className="relative z-10 block flex items-center gap-2">
                📧 Gmail Inbox
              </span>
            </button>
            <button
              onClick={() => setTab('manual')}
              className={`px-8 py-3 rounded-lg font-semibold transition-all duration-300 transform hover:scale-105 relative overflow-hidden group ${
                tab === 'manual'
                  ? 'bg-slate-800/80 text-white border-2 border-red-600'
                  : 'bg-slate-800/30 text-gray-300 hover:bg-slate-800/50 border border-slate-700/50 hover:border-red-600/50'
              }`}
              style={{
                boxShadow: tab === 'manual' ? '0 0 20px rgba(220, 38, 38, 0.5), inset 0 1px 0 rgba(255,255,255,0.05)' : 'inset 0 1px 0 rgba(255,255,255,0.02)',
              }}
            >
              {tab === 'manual' && (
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-red-600/20 to-transparent" 
                  style={{animation: 'shimmer 3s infinite'}}
                ></div>
              )}
              <span className="relative z-10 block flex items-center gap-2">
                📋 Manual Detection
              </span>
            </button>
          </div>
        </div>

        <style>{`
          @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
          }

          @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
          }

          @keyframes lightRay {
            0%, 100% { transform: translateX(-100%); opacity: 0; }
            50% { transform: translateX(100%); opacity: 1; }
          }

          @keyframes floatBob {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-8px); }
          }

          @keyframes pulseGlow {
            0%, 100% { 
              transform: scale(1);
              opacity: 0.3;
            }
            50% { 
              transform: scale(1.2);
              opacity: 0.6;
            }
          }

          @keyframes spin360 {
            0% { transform: rotateZ(0deg); }
            100% { transform: rotateZ(360deg); }
          }

          @keyframes textGlide {
            from {
              opacity: 0;
              transform: translateX(-20px);
            }
            to {
              opacity: 1;
              transform: translateX(0);
            }
          }

          @keyframes fadeUpSlide {
            from {
              opacity: 0;
              transform: translateY(10px);
            }
            to {
              opacity: 1;
              transform: translateY(0);
            }
          }

          @keyframes waveSlide {
            0%, 100% { transform: translateX(-100%); }
            50% { transform: translateX(100%); }
          }

          @keyframes bounceIn {
            0% {
              opacity: 0;
              transform: scale(0.3);
            }
            50% {
              opacity: 1;
              transform: scale(1.05);
            }
            100% {
              opacity: 1;
              transform: scale(1);
            }
          }
        `}</style>
      </nav>

      {/* Content Area */}
      <div className="relative z-10 flex-1">
        {tab === 'gmail' ? (
          selectedEmail ? (
            <EmailDetailPage email={selectedEmail} onBack={() => setSelectedEmail(null)} />
          ) : (
            <HighRiskInbox onEmailSelect={setSelectedEmail} cachedEmails={cachedEmails} setCachedEmails={setCachedEmails} />
          )
        ) : (
          <div className="max-w-7xl mx-auto px-6 py-8 w-full">
            <div className="flex flex-col lg:flex-row gap-8">
              <div className="w-full lg:w-1/3">
                <EmailList emails={analyses} selected={selectedIdx} onSelect={setSelectedIdx} />
              </div>
              <div className="w-full lg:w-2/3">
                <DetectionForm onDetect={handleDetection} />
                {analyses.length > 0 && analyses[selectedIdx] && (
                  <EmailDetail email={analyses[selectedIdx]} />
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
