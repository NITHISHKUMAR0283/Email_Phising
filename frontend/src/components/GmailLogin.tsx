import React, { useState } from 'react';
import { login } from '../api';
import { Mail, Shield } from 'lucide-react';

interface GmailLoginProps {
  onLoginSuccess: () => void;
}

export default function GmailLogin({ onLoginSuccess }: GmailLoginProps) {
  const [isLoading, setIsLoading] = useState(false);

  const handleGmailLogin = async () => {
    setIsLoading(true);
    try {
      // This will redirect to the OAuth flow
      login();
    } catch (error) {
      console.error('Login error:', error);
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800 flex overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-500/10 rounded-full filter blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full filter blur-3xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>

      {/* Left Side - Branding */}
      <div className="hidden lg:flex w-1/2 flex-col justify-between p-12 relative z-10">
        {/* Logo and Title */}
        <div className="flex items-center gap-4">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-red-500 to-red-600 rounded-lg blur opacity-75 animate-pulse"></div>
            <div className="relative bg-slate-900 px-3 py-2 rounded-lg">
              <Shield className="w-8 h-8 text-red-500" strokeWidth={3} />
            </div>
          </div>
          <div>
            <h1 className="text-3xl font-black text-white tracking-tight">
              PhishGuard <span className="text-red-500">AI</span>
            </h1>
            <p className="text-sm text-slate-400 mt-1">Intelligent Email Threat Detection</p>
          </div>
        </div>

        {/* Welcome Message */}
        <div className="space-y-6">
          <div>
            <h2 className="text-6xl font-black text-white mb-2 leading-tight">
              Secure Your <span className="text-red-500">Gmail</span>
            </h2>
            <div className="w-24 h-1 bg-gradient-to-r from-red-500 to-red-600 rounded-full"></div>
          </div>
          <p className="text-slate-400 text-lg max-w-md leading-relaxed">
            Protect your organization from advanced phishing attacks with our AI-powered email security platform.
          </p>

          {/* Feature highlights */}
          <div className="space-y-3 pt-8">
            <div className="flex items-center gap-3 text-slate-300">
              <div className="w-2 h-2 bg-red-500 rounded-full"></div>
              <span className="text-sm">Real-time threat detection</span>
            </div>
            <div className="flex items-center gap-3 text-slate-300">
              <div className="w-2 h-2 bg-red-500 rounded-full"></div>
              <span className="text-sm">Machine learning analysis</span>
            </div>
            <div className="flex items-center gap-3 text-slate-300">
              <div className="w-2 h-2 bg-red-500 rounded-full"></div>
              <span className="text-sm">Enterprise-grade security</span>
            </div>
          </div>
        </div>

        {/* Footer text */}
        <p className="text-slate-500 text-xs">
          © 2026 PhishGuard AI. All rights reserved.
        </p>
      </div>

      {/* Right Side - Login Card */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 lg:p-0 relative z-10">
        {/* Glassmorphism Card */}
        <div
          className="w-full max-w-md backdrop-blur-xl bg-white/10 border border-white/20 rounded-2xl p-8 shadow-2xl
          hover:shadow-2xl hover:shadow-red-500/20 transition-all duration-500 animate-fade-in"
        >
          {/* Card Header */}
          <div className="mb-8">
            <h3 className="text-3xl font-bold text-white mb-2">Welcome Back</h3>
            <p className="text-slate-300 text-sm">Connect your Gmail account to analyze your inbox</p>
          </div>

          {/* Gmail Login Button */}
          <button
            onClick={handleGmailLogin}
            disabled={isLoading}
            className="w-full flex items-center justify-center gap-3 bg-white/20 hover:bg-white/30 disabled:bg-white/10 
                       border border-white/40 hover:border-white/60 disabled:border-white/20
                       rounded-lg py-4 px-6 text-white font-semibold transition-all duration-300
                       disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Mail className="w-5 h-5" />
            {isLoading ? 'Connecting...' : 'Login with Gmail'}
          </button>

          {/* Divider */}
          <div className="relative my-8">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-white/20"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-slate-900/50 backdrop-blur text-slate-400">or continue with</span>
            </div>
          </div>

          {/* Info Box */}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <p className="text-sm text-slate-300 leading-relaxed">
              <span className="font-semibold text-white">🔒 Your data is secure</span>
              <br />
              We use industry-standard OAuth 2.0 authentication. Your password is never stored.
            </p>
          </div>

          {/* Features List */}
          <div className="mt-8 pt-8 border-t border-white/10">
            <p className="text-xs text-slate-400 mb-4 font-semibold">What you get:</p>
            <ul className="space-y-2">
              <li className="text-xs text-slate-300 flex items-center gap-2">
                <svg className="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>Automatic email scanning</span>
              </li>
              <li className="text-xs text-slate-300 flex items-center gap-2">
                <svg className="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>Phishing threat analysis</span>
              </li>
              <li className="text-xs text-slate-300 flex items-center gap-2">
                <svg className="w-4 h-4 text-red-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                <span>Real-time risk scoring</span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
