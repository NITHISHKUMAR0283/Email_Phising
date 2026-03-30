// Global theme and styling constants
export const theme = {
  colors: {
    // Background colors
    background: {
      primary: '#0f1419',      // Very dark blue
      secondary: '#1a1f2e',    // Dark blue
      tertiary: '#242d3d',     // Slightly lighter dark blue
      hover: '#2d3748',        // Hover state
    },
    
    // Risk level colors
    risk: {
      critical: '#dc2626',     // Red
      high: '#ea580c',         // Orange-Red
      medium: '#f59e0b',       // Orange
      low: '#10b981',          // Green
      safe: '#059669',         // Dark Green
    },
    
    // Text colors
    text: {
      primary: '#ffffff',      // White
      secondary: '#d1d5db',    // Light gray
      tertiary: '#9ca3af',     // Medium gray
      muted: '#6b7280',        // Dark gray
    },
    
    // Accent colors
    accent: {
      blue: '#3b82f6',
      cyan: '#06b6d4',
      purple: '#a855f7',
    },
    
    // Border colors
    border: {
      light: '#374151',
      medium: '#4b5563',
      dark: '#1f2937',
    },
  },
  
  // Risk level styling
  riskStyles: {
    critical: {
      bg: 'bg-red-950',
      border: 'border-red-700',
      text: 'text-red-200',
      badge: 'bg-red-600 text-white',
    },
    high: {
      bg: 'bg-orange-950',
      border: 'border-orange-700',
      text: 'text-orange-200',
      badge: 'bg-orange-600 text-white',
    },
    medium: {
      bg: 'bg-amber-950',
      border: 'border-amber-700',
      text: 'text-amber-200',
      badge: 'bg-amber-600 text-white',
    },
    low: {
      bg: 'bg-emerald-950',
      border: 'border-emerald-700',
      text: 'text-emerald-200',
      badge: 'bg-emerald-600 text-white',
    },
    safe: {
      bg: 'bg-green-950',
      border: 'border-green-700',
      text: 'text-green-200',
      badge: 'bg-green-600 text-white',
    },
  },
};

export const getRiskStyle = (score: number | string | undefined) => {
  let level = 'low';
  
  if (typeof score === 'number') {
    if (score >= 0.8) level = 'critical';
    else if (score >= 0.65) level = 'high';
    else if (score >= 0.45) level = 'medium';
    else if (score >= 0.2) level = 'low';
    else level = 'safe';
  } else if (typeof score === 'string') {
    level = score.toLowerCase();
  }
  
  return theme.riskStyles[level as keyof typeof theme.riskStyles] || theme.riskStyles.low;
};

export default theme;
