
import DetectionForm from './components/DetectionForm';
import EmailList from './components/EmailList';
import EmailDetail from './components/EmailDetail';
import HighRiskInbox from './components/HighRiskInbox';
import ParticleBackground from './components/ParticleBackground';
import React, { useState, useEffect } from 'react';

function App() {
  const [analyses, setAnalyses] = useState<any[]>([]);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const [tab, setTab] = useState<'gmail' | 'manual'>('gmail');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);

  // Check authentication on mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex flex-col">
      {/* Animated Background Blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <div className="absolute top-20 left-10 w-72 h-72 bg-blue-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 right-10 w-72 h-72 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      {/* 3D Particle Background */}
      <div className="fixed inset-0 pointer-events-none z-0 opacity-40">
        <ParticleBackground />
      </div>

      {/* Header Navigation with 3D Card Effect */}
      <nav 
        className="relative z-20 border-b border-slate-700/50 backdrop-blur-sm overflow-hidden" 
        style={{perspective: '1200px'}}
      >
        {/* Animated Gradient Background */}
        <div 
          className="absolute inset-0 opacity-30 pointer-events-none"
          style={{
            background: 'linear-gradient(45deg, #0ea5e9, #06b6d4, #0ea5e9)',
            backgroundSize: '400% 400%',
            animation: 'gradientShift 8s ease infinite'
          }}
        ></div>

        {/* Animated Light Ray Effect */}
        <div 
          className="absolute inset-0 pointer-events-none overflow-hidden"
          style={{
            background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.2), transparent)',
            animation: 'lightRay 3s ease-in-out infinite'
          }}
        ></div>

        <div 
          className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center rounded-b-2xl bg-gradient-to-b from-slate-800/60 to-slate-800/30 border-t border-slate-600/30 transition-all duration-500 transform hover:shadow-2xl hover:shadow-blue-500/30 relative z-10"
          style={{
            boxShadow: `
              0 20px 60px rgba(0, 0, 0, 0.8),
              inset 0 1px 0 rgba(255, 255, 255, 0.1),
              inset 0 -1px 0 rgba(0, 0, 0, 0.5)
            `,
            backdropFilter: 'blur(20px)',
          }}
          onMouseMove={(e) => {
            const rect = e.currentTarget.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            const rotateX = ((y - centerY) / centerY) * 5;
            const rotateY = ((centerX - x) / centerX) * 5;
            
            e.currentTarget.style.transform = `perspective(1200px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateZ(10px)`;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'perspective(1200px) rotateX(0) rotateY(0) translateZ(0)';
          }}
        >
          {/* Logo and Title */}
          <div className="flex items-center gap-3 group relative">
            {/* Glow Background for Logo */}
            <div 
              className="absolute w-16 h-16 bg-gradient-to-r from-blue-500/40 to-cyan-500/40 rounded-full blur-xl -inset-2 group-hover:from-blue-500/60 group-hover:to-cyan-500/60 transition-all duration-500"
              style={{animation: 'pulseGlow 3s ease-in-out infinite'}}
            ></div>

            <div 
              className="w-12 h-12 bg-gradient-to-br from-blue-400 via-blue-500 to-blue-600 rounded-xl flex items-center justify-center transform group-hover:scale-110 transition-all duration-300 shadow-lg relative z-10" 
              style={{
                boxShadow: 'inset -2px -2px 10px rgba(0,0,0,0.3), inset 2px 2px 10px rgba(255,255,255,0.2), 0 0 20px rgba(59,130,246,0.5)',
                animation: 'floatBob 3s ease-in-out infinite'
              }}
            >
              <span className="text-xl" style={{animation: 'spin360 4s linear infinite'}}>🛡️</span>
            </div>

            <div className="transform group-hover:translate-x-2 transition-transform duration-300 relative z-10">
              <h1 
                className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-300 via-blue-400 to-cyan-400"
                style={{
                  animation: 'textGlide 0.8s ease-out',
                  backgroundSize: '300% 300%',
                }}
              >
                PhishGuard AI
              </h1>
              <p 
                className="text-blue-300/80 text-sm font-medium"
                style={{animation: 'fadeUpSlide 0.8s ease-out 0.2s both'}}
              >
                Intelligent Email Threat Detection
              </p>
            </div>
          </div>

          {/* Auth Button - Sign in / Logged in */}
          {!checkingAuth && (
            isAuthenticated ? (
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 px-4 py-2 bg-green-500/20 border border-green-500/50 rounded-xl">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-green-300 font-semibold">✓ Logged In</span>
                </div>
                <button
                  onClick={() => {
                    setIsAuthenticated(false);
                    window.location.href = 'http://localhost:8000/logout';
                  }}
                  className="px-6 py-3 bg-gradient-to-r from-red-500 to-red-600 text-white rounded-xl font-semibold hover:from-red-600 hover:to-red-700 transition-all duration-300 transform hover:scale-105 shadow-lg hover:shadow-red-500/50 border border-red-400/30"
                >
                  Logout
                </button>
              </div>
            ) : (
              <button
                onClick={() => window.location.href = 'http://localhost:8000/login'}
                className="px-8 py-3 bg-gradient-to-r from-blue-500 via-blue-600 to-blue-700 text-white rounded-xl font-semibold hover:from-blue-600 hover:to-blue-800 transition-all duration-300 transform hover:scale-110 hover:-translate-y-1 shadow-lg hover:shadow-blue-500/70 whitespace-nowrap border border-blue-400/30 backdrop-blur-sm relative overflow-hidden group"
                style={{
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.2), 0 10px 30px rgba(59,130,246,0.4)',
                }}
              >
                {/* Wave Effect */}
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
                  style={{animation: 'waveSlide 2s ease-in-out infinite'}}
                ></div>
                <span className="relative z-10 block">Sign in with Google</span>
              </button>
            )
          )}
        </div>

        {/* Tab Navigation with 3D Effects */}
        <div className="border-t border-slate-700/50 px-6 py-3 bg-gradient-to-r from-slate-800/40 to-slate-700/40 relative z-10">
          <div className="max-w-7xl mx-auto flex gap-4">
            <button
              onClick={() => setTab('gmail')}
              className={`px-8 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 relative overflow-hidden group ${
                tab === 'gmail'
                  ? 'bg-gradient-to-br from-blue-500 via-blue-600 to-blue-700 text-white shadow-lg hover:shadow-blue-500/50'
                  : 'bg-slate-700/30 text-blue-300 hover:bg-slate-700/50 border border-slate-600/40 hover:border-blue-500/50'
              }`}
              style={{
                boxShadow: tab === 'gmail' ? 'inset 0 1px 0 rgba(255,255,255,0.2), 0 8px 20px rgba(59,130,246,0.3)' : 'inset 0 1px 0 rgba(255,255,255,0.05)',
              }}
            >
              {tab === 'gmail' && (
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12" 
                  style={{animation: 'shimmer 3s infinite'}}
                ></div>
              )}
              <div className="absolute inset-0 bg-gradient-to-t from-blue-600/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <span className="relative z-10 block" style={{animation: tab === 'gmail' ? 'bounceIn 0.6s ease-out' : 'none'}}>
                📧 Gmail Inbox
              </span>
            </button>
            <button
              onClick={() => setTab('manual')}
              className={`px-8 py-3 rounded-xl font-semibold transition-all duration-300 transform hover:scale-105 relative overflow-hidden group ${
                tab === 'manual'
                  ? 'bg-gradient-to-br from-blue-500 via-blue-600 to-blue-700 text-white shadow-lg hover:shadow-blue-500/50'
                  : 'bg-slate-700/30 text-blue-300 hover:bg-slate-700/50 border border-slate-600/40 hover:border-blue-500/50'
              }`}
              style={{
                boxShadow: tab === 'manual' ? 'inset 0 1px 0 rgba(255,255,255,0.2), 0 8px 20px rgba(59,130,246,0.3)' : 'inset 0 1px 0 rgba(255,255,255,0.05)',
              }}
            >
              {tab === 'manual' && (
                <div 
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent transform -skew-x-12" 
                  style={{animation: 'shimmer 3s infinite'}}
                ></div>
              )}
              <div className="absolute inset-0 bg-gradient-to-t from-blue-600/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
              <span className="relative z-10 block" style={{animation: tab === 'manual' ? 'bounceIn 0.6s ease-out' : 'none'}}>
                ✏️ Manual Detection
              </span>
            </button>
          </div>
        </div>

        <style>{`
          @keyframes shimmer {
            0% { transform: translateX(-100%) skewX(-12deg); }
            100% { transform: translateX(100%) skewX(-12deg); }
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
          <HighRiskInbox />
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
