import React from 'react';

interface PhishGuardLogoLoginProps {
  size?: number;
}

const PhishGuardLogoLogin: React.FC<PhishGuardLogoLoginProps> = ({ size = 40 }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="drop-shadow-[0_0_10px_rgba(220,38,38,0.4)]"
    >
      {/* Outer circle glow */}
      <circle cx="20" cy="20" r="19" fill="none" stroke="url(#glowGradient)" strokeWidth="0.5" opacity="0.6" />

      {/* Shield background */}
      <path
        d="M20 3L35 9V18C35 28 20 35 20 35C20 35 5 28 5 18V9L20 3Z"
        fill="url(#shieldGradient)"
        stroke="url(#boarderGradient)"
        strokeWidth="1.5"
      />

      {/* Email envelope */}
      <rect x="12" y="14" width="16" height="11" rx="1" fill="none" stroke="#e0f2fe" strokeWidth="1.2" />
      <path d="M12 14L20 20L28 14" fill="none" stroke="#e0f2fe" strokeWidth="1.2" strokeLinecap="round" />

      {/* Fishing hook - curved line from bottom right */}
      <path
        d="M28 22C28 24 27 26 25 27C23 28 21 27.5 21 26"
        fill="none"
        stroke="#dc2626"
        strokeWidth="1.5"
        strokeLinecap="round"
      />

      {/* Hook point */}
      <circle cx="21" cy="26" r="0.8" fill="#dc2626" />

      {/* Shield circuit lines */}
      <circle cx="20" cy="20" r="3" fill="none" stroke="url(#circuitGradient)" strokeWidth="0.8" opacity="0.5" />
      <line x1="20" y1="17" x2="20" y2="23" stroke="url(#circuitGradient)" strokeWidth="0.7" opacity="0.4" />
      <line x1="17" y1="20" x2="23" y2="20" stroke="url(#circuitGradient)" strokeWidth="0.7" opacity="0.4" />

      {/* Gradients */}
      <defs>
        <linearGradient id="shieldGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#1f2937', stopOpacity: 1 }} />
          <stop offset="100%" style={{ stopColor: '#111827', stopOpacity: 1 }} />
        </linearGradient>

        <linearGradient id="boarderGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#dc2626', stopOpacity: 0.8 }} />
          <stop offset="100%" style={{ stopColor: '#b91c1c', stopOpacity: 0.6 }} />
        </linearGradient>

        <linearGradient id="glowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#dc2626', stopOpacity: 0.8 }} />
          <stop offset="100%" style={{ stopColor: '#f87171', stopOpacity: 0.6 }} />
        </linearGradient>

        <linearGradient id="circuitGradient" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#06b6d4', stopOpacity: 0.8 }} />
          <stop offset="100%" style={{ stopColor: '#0891b2', stopOpacity: 0.6 }} />
        </linearGradient>
      </defs>
    </svg>
  );
};

export default PhishGuardLogoLogin;
