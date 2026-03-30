import React, { useState, useEffect } from 'react';
import GmailLogin from './components/GmailLogin';
import HighRiskInbox from './components/HighRiskInbox';
import EmailDetailPage from './components/EmailDetailPage';
import ParticleBackground from './components/ParticleBackground';
import { logout, checkAuth } from './api';

type AppPage = 'login' | 'inbox' | 'detail';

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
  reasons?: string[];
  risk_level?: string;
  confidence?: number;
}

function App() {
  const [currentPage, setCurrentPage] = useState<AppPage>('login');
  const [selectedEmail, setSelectedEmail] = useState<EmailData | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [cachedEmails, setCachedEmails] = useState<EmailData[]>([]);

  // Check authentication on mount and handle OAuth callback
  useEffect(() => {
    const checkAuthStatus = async () => {
      // Check for OAuth callback token in URL
      const params = new URLSearchParams(window.location.search);
      const callbackToken = params.get('token');
      
      if (callbackToken) {
        // Save token from OAuth callback
        localStorage.setItem('gmail_access_token', callbackToken);
        // Clean up URL
        window.history.replaceState({}, document.title, window.location.pathname);
      }
      
      const token = localStorage.getItem('gmail_access_token');
      const isAuth = await checkAuth(token || undefined);
      if (isAuth) {
        setIsAuthenticated(true);
        setCurrentPage('inbox');
      }
    };
    checkAuthStatus();
  }, []);

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    setCurrentPage('inbox');
  };

  const handleEmailSelect = (email: EmailData) => {
    setSelectedEmail(email);
    setCurrentPage('detail');
  };

  const handleBackFromDetail = () => {
    setSelectedEmail(null);
    setCurrentPage('inbox');
  };

  const handleLogout = async () => {
    await logout();
    setIsAuthenticated(false);
    setCachedEmails([]);
    setCurrentPage('login');
  };

  return (
    <div className="relative w-full h-screen bg-[#020617]">
      <ParticleBackground />
      {currentPage === 'login' && (
        <GmailLogin onLoginSuccess={handleLoginSuccess} />
      )}
      {currentPage === 'inbox' && isAuthenticated && (
        <div className="relative z-10 w-full h-full overflow-y-auto">
          <div className="p-6">
            <div className="max-w-7xl mx-auto">
              {/* Header */}
              <div className="mb-8 flex items-center justify-between">
                <div>
                  <h1 className="text-4xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                    🎣 PhishGuard AI
                  </h1>
                  <p className="text-gray-400 mt-2">Gmail Security Analysis</p>
                </div>
                <button
                  onClick={handleLogout}
                  className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-semibold transition-all duration-300"
                >
                  Logout
                </button>
              </div>
              <HighRiskInbox 
                onEmailSelect={handleEmailSelect}
                cachedEmails={cachedEmails}
                setCachedEmails={setCachedEmails}
              />
            </div>
          </div>
        </div>
      )}
      {currentPage === 'detail' && selectedEmail && (
        <EmailDetailPage email={selectedEmail} onBack={handleBackFromDetail} />
      )}
    </div>
  );
}

export default App;
