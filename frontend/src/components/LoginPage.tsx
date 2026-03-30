import React, { useState } from 'react';
import { Mail, Lock } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [focusedField, setFocusedField] = useState(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    setIsLoading(true);
    // Simulate login process
    setTimeout(() => {
      setIsLoading(false);
      console.log('Login attempt:', { email, password });
    }, 1500);
  };

  return (
    <div className="min-h-screen flex overflow-hidden bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
      {/* Animated background gradients */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-600 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-red-600 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-pulse" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 right-0 w-96 h-96 bg-purple-600 rounded-full mix-blend-multiply filter blur-3xl opacity-5 animate-pulse" style={{ animationDelay: '4s' }}></div>
      </div>

      {/* Left Side - Branding & Welcome */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 relative z-10">
        {/* Logo & Title */}
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center shadow-lg shadow-red-500/50 hover:shadow-red-500/70 transition-all duration-300">
            <div className="text-xl font-bold text-white">🎣</div>
          </div>
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
              PhishGuard AI
            </h1>
            <p className="text-sm text-gray-400 mt-1">Intelligent Email Threat Detection</p>
          </div>
        </div>

        {/* Welcome Section */}
        <div className="space-y-6">
          <div>
            <h2 className="text-5xl md:text-6xl font-bold text-white leading-tight">
              Welcome{' '}
              <span className="bg-gradient-to-r from-red-500 to-red-600 bg-clip-text text-transparent animate-pulse">
                Back
              </span>
            </h2>
            <p className="text-gray-400 mt-4 text-lg leading-relaxed">
              Protect your organization from phishing attacks with AI-powered email threat detection and analysis.
            </p>
          </div>

          {/* Feature highlights */}
          <div className="flex flex-col gap-4">
            {[
              { icon: '⚡', text: 'Real-time threat detection' },
              { icon: '🛡️', text: 'Advanced ML algorithms' },
              { icon: '📊', text: 'Detailed threat analytics' }
            ].map((item, idx) => (
              <div key={idx} className="flex items-center gap-3 text-gray-300 hover:text-white transition-colors">
                <span className="text-2xl">{item.icon}</span>
                <span>{item.text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer text */}
        <div className="text-sm text-gray-500">
          Enterprise-grade security for modern teams
        </div>
      </div>

      {/* Right Side - Login Card */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 sm:p-12 relative z-10">
        <div className="w-full max-w-md animate-fade-in">
          {/* Glassmorphism Card */}
          <div className="bg-white/10 backdrop-blur-xl rounded-2xl p-8 sm:p-10 border border-white/20 shadow-2xl hover:border-white/30 transition-all duration-500 hover:shadow-red-500/10">
            {/* Card Header */}
            <div className="mb-8">
              <h3 className="text-3xl font-bold text-white mb-2">Sign In</h3>
              <div className="h-1 w-16 bg-gradient-to-r from-red-500 to-red-600 rounded-full"></div>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Email Field */}
              <div className="space-y-2">
                <label htmlFor="email" className="block text-sm font-medium text-gray-300">
                  Email Address
                </label>
                <div
                  className={`relative transition-all duration-300 ${
                    focusedField === 'email' ? 'transform scale-105' : ''
                  }`}
                >
                  <div
                    className={`absolute inset-0 bg-gradient-to-r from-red-600 to-red-400 rounded-lg blur opacity-0 transition-all duration-300 ${
                      focusedField === 'email' ? 'opacity-50' : ''
                    }`}
                  ></div>
                  <div className="relative">
                    <Mail className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      onFocus={() => setFocusedField('email')}
                      onBlur={() => setFocusedField(null)}
                      placeholder="Enter your email"
                      className={`w-full pl-12 pr-4 py-3 bg-slate-900/50 text-white placeholder-gray-500 rounded-lg border-2 transition-all duration-300 focus:outline-none ${
                        focusedField === 'email'
                          ? 'border-red-500 bg-slate-900/70 shadow-lg shadow-red-500/20'
                          : 'border-gray-700 hover:border-gray-600'
                      }`}
                      required
                    />
                  </div>
                </div>
              </div>

              {/* Password Field */}
              <div className="space-y-2">
                <label htmlFor="password" className="block text-sm font-medium text-gray-300">
                  Password
                </label>
                <div
                  className={`relative transition-all duration-300 ${
                    focusedField === 'password' ? 'transform scale-105' : ''
                  }`}
                >
                  <div
                    className={`absolute inset-0 bg-gradient-to-r from-red-600 to-red-400 rounded-lg blur opacity-0 transition-all duration-300 ${
                      focusedField === 'password' ? 'opacity-50' : ''
                    }`}
                  ></div>
                  <div className="relative">
                    <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onFocus={() => setFocusedField('password')}
                      onBlur={() => setFocusedField(null)}
                      placeholder="Enter your password"
                      className={`w-full pl-12 pr-4 py-3 bg-slate-900/50 text-white placeholder-gray-500 rounded-lg border-2 transition-all duration-300 focus:outline-none ${
                        focusedField === 'password'
                          ? 'border-red-500 bg-slate-900/70 shadow-lg shadow-red-500/20'
                          : 'border-gray-700 hover:border-gray-600'
                      }`}
                      required
                    />
                  </div>
                </div>
              </div>

              {/* Remember Me & Forgot Password */}
              <div className="flex items-center justify-between">
                <label className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    className="w-4 h-4 rounded bg-slate-900 border-gray-700 text-red-500 focus:ring-red-500 cursor-pointer"
                  />
                  <span className="text-sm text-gray-400 group-hover:text-gray-300 transition-colors">
                    Remember me
                  </span>
                </label>
                <a href="#" className="text-sm text-red-500 hover:text-red-400 transition-colors font-medium">
                  Forgot password?
                </a>
              </div>

              {/* Sign In Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="relative w-full mt-8 group"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-red-600 to-red-500 rounded-lg blur opacity-0 group-hover:opacity-100 transition-all duration-500 group-hover:blur-lg group-disabled:opacity-50"></div>
                <div className="relative flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-red-600 to-red-500 text-white font-semibold rounded-lg hover:from-red-700 hover:to-red-600 transition-all duration-300 group-hover:shadow-lg group-hover:shadow-red-500/50 disabled:opacity-70 disabled:cursor-not-allowed">
                  {isLoading ? (
                    <>
                      <span className="inline-block animate-spin">⏳</span>
                      Signing in...
                    </>
                  ) : (
                    <>
                      Sign In
                      <span className="group-hover:translate-x-1 transition-transform duration-300">→</span>
                    </>
                  )}
                </div>
              </button>
            </form>

            {/* Security Badge */}
            <div className="mt-8 pt-6 border-t border-white/10 flex items-center justify-center gap-2 text-xs text-gray-400">
              <span>🔒</span>
              <span>Enterprise-grade encryption</span>
            </div>
          </div>

          {/* Mobile Logo (shown on small screens) */}
          <div className="lg:hidden mt-8 text-center">
            <div className="flex items-center justify-center gap-2 mb-4">
              <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-red-600 rounded-lg flex items-center justify-center shadow-lg shadow-red-500/50">
                <div className="text-lg font-bold text-white">🎣</div>
              </div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                PhishGuard AI
              </h1>
            </div>
            <p className="text-sm text-gray-400">Intelligent Email Threat Detection</p>
          </div>
        </div>
      </div>

      {/* Custom Animation */}
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
