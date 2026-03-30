import React from 'react';

interface PhishGuardLogoProps {
  size?: number;
  className?: string;
}

const PhishGuardLogo: React.FC<PhishGuardLogoProps> = ({ size = 120, className = '' }) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 120 140"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={{ filter: 'drop-shadow(0 0 8px rgba(220, 38, 38, 0.3))' }}
    >
      <defs>
        {/* Gradient definitions */}
        <linearGradient id="shieldGradient" x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" style={{ stopColor: '#dc2626', stopOpacity: 0.1 }} />
          <stop offset="100%" style={{ stopColor: '#991b1b', stopOpacity: 0.05 }} />
        </linearGradient>

        <radialGradient id="circuitGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" style={{ stopColor: '#06b6d4', stopOpacity: 0.4 }} />
          <stop offset="100%" style={{ stopColor: '#06b6d4', stopOpacity: 0 }} />
        </radialGradient>

        <filter id="glow">
          <feGaussianBlur stdDeviation="1.5" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/* Main Shield Outline - Deep Crimson Red */}
      <path
        d="M 60 15 L 45 30 L 45 65 Q 45 95 60 120 Q 75 95 75 65 L 75 30 Z"
        fill="url(#shieldGradient)"
        stroke="#dc2626"
        strokeWidth="2.5"
        strokeLinejoin="round"
      />

      {/* Circuit Glow Background */}
      <circle cx="60" cy="65" r="28" fill="url(#circuitGlow)" opacity="0.6" />

      {/* Circuit Nodes - Silver/Charcoal - forming subtle fishing hook shape */}
      
      {/* Top node (hook eye) */}
      <circle cx="60" cy="40" r="3.5" fill="#c0c0c0" filter="url(#glow)" />
      
      {/* Upper-right node (hook curve) */}
      <circle cx="70" cy="50" r="3" fill="#a1a1aa" />
      
      {/* Right node (hook curve) */}
      <circle cx="74" cy="65" r="3" fill="#a1a1aa" />
      
      {/* Lower-right node (hook barb) */}
      <circle cx="70" cy="78" r="2.5" fill="#71717a" />
      
      {/* Bottom node (hook point curve) */}
      <circle cx="60" cy="85" r="3" fill="#a1a1aa" />
      
      {/* Lower-left node (hook return) */}
      <circle cx="50" cy="78" r="2.5" fill="#71717a" />
      
      {/* Left node */}
      <circle cx="46" cy="65" r="3" fill="#a1a1aa" />
      
      {/* Upper-left node */}
      <circle cx="50" cy="50" r="3" fill="#a1a1aa" />

      {/* Circuit Lines - forming subtle fishing hook shape */}
      
      {/* Hook curve - right side */}
      <path
        d="M 60 40 Q 70 45 74 65 Q 70 80 60 85"
        stroke="#a1a1aa"
        strokeWidth="1.5"
        fill="none"
        strokeLinecap="round"
        opacity="0.8"
      />

      {/* Hook return - left side */}
      <path
        d="M 60 85 Q 50 80 46 65 Q 50 45 60 40"
        stroke="#a1a1aa"
        strokeWidth="1.5"
        fill="none"
        strokeLinecap="round"
        opacity="0.8"
      />

      {/* Subtle horizontal cross-connections */}
      <line x1="50" y1="50" x2="70" y2="50" stroke="#71717a" strokeWidth="1" opacity="0.5" />
      <line x1="46" y1="65" x2="74" y2="65" stroke="#71717a" strokeWidth="1" opacity="0.5" />
      <line x1="50" y1="78" x2="70" y2="78" stroke="#71717a" strokeWidth="1" opacity="0.5" />

      {/* AI Center Core - subtle grid overlay for intelligence representation */}
      <g opacity="0.4">
        <circle cx="60" cy="65" r="12" fill="none" stroke="#06b6d4" strokeWidth="0.8" />
        <circle cx="60" cy="65" r="8" fill="none" stroke="#06b6d4" strokeWidth="0.8" />
        <line x1="60" y1="60" x2="60" y2="70" stroke="#06b6d4" strokeWidth="0.8" />
        <line x1="55" y1="65" x2="65" y2="65" stroke="#06b6d4" strokeWidth="0.8" />
      </g>

      {/* Envelope Symbol - Top Center of Shield */}
      {/* Envelope background */}
      <rect x="52" y="22" width="16" height="12" fill="none" stroke="#c0c0c0" strokeWidth="1.5" rx="1" />
      
      {/* Envelope flap (letter shape) */}
      <path
        d="M 52 22 L 60 27.5 L 68 22"
        fill="none"
        stroke="#c0c0c0"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      
      {/* Subtle envelope line */}
      <line x1="52" y1="22" x2="60" y2="27.5" stroke="#a1a1aa" strokeWidth="1" opacity="0.6" />
      <line x1="68" y1="22" x2="60" y2="27.5" stroke="#a1a1aa" strokeWidth="1" opacity="0.6" />

      {/* Shield accent glow - right side */}
      <path
        d="M 60 15 L 45 30 L 45 65 Q 45 95 60 120 Q 75 95 75 65 L 75 30 Z"
        fill="none"
        stroke="#dc2626"
        strokeWidth="1"
        opacity="0.3"
        filter="url(#glow)"
      />
    </svg>
  );
};

export default PhishGuardLogo;
