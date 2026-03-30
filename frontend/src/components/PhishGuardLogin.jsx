import React, { useState } from 'react';
import { Mail, Lock, Shield } from 'lucide-react';

export default function PhishGuardLogin({ onLoginSuccess }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    // Simulate API call
    setTimeout(() => {
      if (!email || !password) {
        setError('Please fill in all fields');
      } else {
        console.log('Login attempt:', { email, password });
        // Handle login logic here
        if (onLoginSuccess) {
          onLoginSuccess();
        }
      }
      setIsLoading(false);
    }, 1000);
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
              Welcome <span className="text-red-500">Back</span>
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
          © 2024 PhishGuard AI. All rights reserved.
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
            <h3 className="text-3xl font-bold text-white mb-2">Sign In</h3>
            <p className="text-slate-300 text-sm">Enter your credentials to continue</p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-6 p-4 bg-red-500/20 border border-red-500/50 rounded-lg">
              <p className="text-red-200 text-sm">{error}</p>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Email Input */}
            <div className="space-y-2">
              <label htmlFor="email" className="block text-sm font-medium text-slate-200">
                Email Address
              </label>
              <div className="relative group">
                <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  className="w-full bg-slate-800/50 border border-slate-700/50 rounded-lg py-3 pl-12 pr-4 text-white placeholder-slate-500
                  focus:outline-none focus:border-red-500/50 focus:ring-2 focus:ring-red-500/20 focus:shadow-lg focus:shadow-red-500/10
                  transition-all duration-300 backdrop-blur-sm"
                />
              </div>
            </div>

            {/* Password Input */}
            <div className="space-y-2">
              <label htmlFor="password" className="block text-sm font-medium text-slate-200">
                Password
              </label>
              <div className="relative group">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-400 group-focus-within:text-red-500 transition-colors" />
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="w-full bg-slate-800/50 border border-slate-700/50 rounded-lg py-3 pl-12 pr-4 text-white placeholder-slate-500
                  focus:outline-none focus:border-red-500/50 focus:ring-2 focus:ring-red-500/20 focus:shadow-lg focus:shadow-red-500/10
                  transition-all duration-300 backdrop-blur-sm"
                />
              </div>
            </div>

            {/* Sign In Button */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-8 relative group overflow-hidden rounded-lg py-3 font-bold text-white transition-all duration-300
              disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {/* Button gradient background */}
              <div className="absolute inset-0 bg-gradient-to-r from-red-600 to-red-500 group-hover:shadow-lg group-hover:shadow-red-500/50 transition-all duration-300"></div>

              {/* Button glow effect on hover */}
              <div className="absolute inset-0 bg-gradient-to-r from-red-500 to-red-400 opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-lg"></div>

              {/* Button text */}
              <span className="relative z-10 flex items-center justify-center gap-2">
                {isLoading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </span>
            </button>
          </form>

          {/* Divider */}
          <div className="my-8 relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-700/50"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-white/10 text-slate-400 backdrop-blur">or continue with</span>
            </div>
          </div>

          {/* SSO Options */}
          <div className="grid grid-cols-2 gap-4">
            <button
              type="button"
              className="px-4 py-2.5 border border-slate-700/50 rounded-lg text-slate-300 text-sm font-medium
              hover:bg-white/5 hover:border-slate-600/50 transition-all duration-200 backdrop-blur-sm"
            >
              Microsoft
            </button>
            <button
              type="button"
              className="px-4 py-2.5 border border-slate-700/50 rounded-lg text-slate-300 text-sm font-medium
              hover:bg-white/5 hover:border-slate-600/50 transition-all duration-200 backdrop-blur-sm"
            >
              Google
            </button>
          </div>

          {/* Footer */}
          <p className="text-center text-slate-400 text-xs mt-8">
            Admin access only. Unauthorized access is prohibited.
          </p>
        </div>
      </div>

      {/* Mobile Logo */}
      <div className="lg:hidden absolute top-6 left-6 z-20">
        <div className="flex items-center gap-2">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-red-500 to-red-600 rounded-lg blur opacity-75"></div>
            <div className="relative bg-slate-900 px-2 py-1 rounded-lg">
              <Shield className="w-5 h-5 text-red-500" strokeWidth={3} />
            </div>
          </div>
          <div>
            <p className="text-sm font-bold text-white">PhishGuard <span className="text-red-500">AI</span></p>
          </div>
        </div>
      </div>

      {/* Add animation keyframes */}
      <style jsx>{`
        @keyframes fade-in {
          from {
            opacity: 0;
            transform: translateY(20px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .animate-fade-in {
          animation: fade-in 0.8s ease-out;
        }
      `}</style>
    </div>
  );
}
