import React, { useState } from 'react';
import InputField from './InputField';
import PhishGuardLogoLogin from './PhishGuardLogoLogin';

const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    
    try {
      // TODO: Integrate with backend authentication
      console.log('Sign in attempt:', { email, password });
      // const response = await fetch('/api/auth/login', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ email, password })
      // });
      // Handle response and redirect
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black overflow-hidden flex">
      {/* Animated background gradient */}
      <div className="fixed inset-0 z-0">
        <div className="absolute inset-0 bg-gradient-to-br from-black via-[#0a0a0a] to-black" />
        
        {/* Glowing light streaks */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-600/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }} />
        
        {/* Grid overlay */}
        <div className="absolute inset-0 opacity-5" style={{
          backgroundImage: 'linear-gradient(0deg, transparent 24%, rgba(220, 38, 38, 0.1) 25%, rgba(220, 38, 38, 0.1) 26%, transparent 27%, transparent 74%, rgba(220, 38, 38, 0.1) 75%, rgba(220, 38, 38, 0.1) 76%, transparent 77%, transparent)',
          backgroundSize: '50px 50px'
        }} />
      </div>

      {/* LEFT SECTION - Branding */}
      <div className="hidden lg:flex lg:w-1/2 flex-col justify-between p-12 relative z-10">
        {/* Logo and Branding */}
        <div className="space-y-3">
          <div className="flex items-center gap-3 group">
            <PhishGuardLogoLogin size={48} />
            <div>
              <h1 className="text-3xl font-bold text-white">PhishGuard AI</h1>
              <p className="text-sm text-zinc-400">Intelligent Email Threat Detection</p>
            </div>
          </div>
        </div>

        {/* Welcome Message */}
        <div className="space-y-6 mb-20">
          <div className="space-y-2">
            <h2 className="text-5xl font-bold text-white leading-tight">
              Welcome <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-red-400">Back</span>
            </h2>
            <p className="text-zinc-400 text-lg">Protect your organization from phishing threats in real-time</p>
          </div>
          
          <div className="space-y-4 text-sm text-zinc-400">
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-red-500 rounded-full" />
              <span>Advanced threat detection and analysis</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-red-500 rounded-full" />
              <span>Real-time email security monitoring</span>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-2 h-2 bg-red-500 rounded-full" />
              <span>Enterprise-grade protection</span>
            </div>
          </div>
        </div>

        {/* Footer */}
        <p className="text-xs text-zinc-600">© 2026 PhishGuard AI. All rights reserved.</p>
      </div>

      {/* RIGHT SECTION - Login Card */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-6 relative z-10">
        <div className="w-full max-w-md">
          {/* Glassmorphism Card */}
          <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl
                          hover:shadow-[0_0_40px_rgba(220,38,38,0.2)] transition-shadow duration-500
                          animate-fade-in">
            
            {/* Title */}
            <h3 className="text-2xl font-bold text-white mb-8">Sign In</h3>

            {/* Form */}
            <form onSubmit={handleSignIn} className="space-y-6">
              <InputField
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />

              <InputField
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />

              {/* Sign In Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-3 px-4 bg-gradient-to-r from-red-600 to-red-500 
                           text-white font-semibold rounded-lg
                           hover:shadow-[0_0_20px_rgba(220,38,38,0.6)] 
                           hover:from-red-500 hover:to-red-400
                           disabled:opacity-50 disabled:cursor-not-allowed
                           transition-all duration-300 transform hover:scale-105
                           active:scale-95 relative overflow-hidden group"
              >
                <span className="relative z-10">
                  {isLoading ? 'Signing In...' : 'Sign In'}
                </span>
                <div className="absolute inset-0 bg-gradient-to-r from-red-400 to-red-600 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </button>
            </form>

            {/* Divider */}
            <div className="my-6 flex items-center gap-4">
              <div className="flex-1 h-px bg-gradient-to-r from-transparent via-zinc-600/30 to-transparent" />
            </div>

            {/* Footer Text */}
            <p className="text-center text-sm text-zinc-400">
              Protected by enterprise-grade security
            </p>
          </div>

          {/* Mobile Branding (visible on small screens) */}
          <div className="lg:hidden mt-8 text-center">
            <h1 className="text-2xl font-bold text-white">PhishGuard AI</h1>
            <p className="text-xs text-zinc-500 mt-2">Intelligent Email Threat Detection</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
