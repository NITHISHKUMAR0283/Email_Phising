import React, { useState } from 'react';

interface SanitizedURLProps {
  urls: string[];
}

export default function SanitizedURL({ urls }: SanitizedURLProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const truncateURL = (url: string, maxLength: number = 50) => {
    if (url.length <= maxLength) return url;
    const start = url.substring(0, 20);
    const end = url.substring(url.length - 20);
    return `${start}...${end}`;
  };

  const copyToClipboard = (url: string, index: number) => {
    navigator.clipboard.writeText(url).then(() => {
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    });
  };

  const getDomainFromURL = (url: string) => {
    try {
      const domain = new URL(url).hostname;
      return domain;
    } catch {
      return 'Invalid URL';
    }
  };

  if (!urls || urls.length === 0) return null;

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-bold text-white flex items-center gap-2">
        <span className="text-2xl">🔗</span> URLs Detected ({urls.length})
      </h3>

      <div className="space-y-3">
        {urls.map((url, idx) => (
          <div
            key={idx}
            className="bg-gradient-to-br from-slate-800/60 to-slate-900/40 border border-red-500/30 rounded-lg p-4 backdrop-blur-sm hover:border-red-500/60 transition-all duration-300"
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="text-xs font-bold text-red-400 uppercase mb-2 tracking-wide">
                  🚨 Suspicious URL #{idx + 1}
                </div>
                <div className="font-mono text-xs bg-slate-900/50 rounded border border-slate-700 p-3 break-all overflow-x-auto text-slate-300 mb-2">
                  {url}
                </div>
                <div className="text-xs text-slate-400 mb-2">
                  <span className="font-semibold">Domain:</span> {getDomainFromURL(url)}
                </div>
                <div className="flex gap-2 text-xs">
                  <span className="bg-orange-900/40 text-orange-300 px-2 py-1 rounded border border-orange-500/30">
                    ⚠️ No HTTPS
                  </span>
                  <span className="bg-red-900/40 text-red-300 px-2 py-1 rounded border border-red-500/30">
                    🚫 Reputation Unknown
                  </span>
                </div>
              </div>

              <button
                onClick={() => copyToClipboard(url, idx)}
                className={`flex-shrink-0 px-3 py-2 rounded-lg font-semibold text-xs transition-all duration-300 ${
                  copiedIndex === idx
                    ? 'bg-green-500/50 text-green-100 border border-green-500'
                    : 'bg-slate-700/50 hover:bg-slate-600/70 text-slate-200 border border-slate-600 hover:border-slate-500'
                }`}
              >
                {copiedIndex === idx ? '✅ Copied!' : '📋 Copy'}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
