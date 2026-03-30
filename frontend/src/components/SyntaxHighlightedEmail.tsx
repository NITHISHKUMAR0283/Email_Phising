import React from 'react';

interface SyntaxHighlightedEmailProps {
  body: string;
  highlightPhrases?: string[];
}

export default function SyntaxHighlightedEmail({ body, highlightPhrases = [] }: SyntaxHighlightedEmailProps) {
  if (!body) {
    return (
      <div className="bg-slate-900/50 border border-slate-700/50 rounded-lg p-6 text-slate-400">
        No email content available
      </div>
    );
  }

  const lines = body.split('\n');

  const highlightLine = (line: string) => {
    if (highlightPhrases.length === 0) return line;

    let highlightedContent: React.ReactNode[] = [];
    let currentText = line;

    highlightPhrases.forEach((phrase) => {
      const regex = new RegExp(`(${phrase})`, 'gi');
      const parts = currentText.split(regex);

      highlightedContent = parts.map((part, idx) => {
        if (phrase.toLowerCase() === part.toLowerCase()) {
          return (
            <span key={idx} className="bg-yellow-500/50 text-yellow-100 font-bold px-1 rounded">
              {part}
            </span>
          );
        }
        return <span key={idx}>{part}</span>;
      });

      currentText = '';
    });

    return highlightedContent || line;
  };

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-bold text-white flex items-center gap-2">
        <span className="text-2xl">📄</span> Email Body (Sanitized View)
      </h3>

      <div className="bg-gradient-to-br from-slate-900/80 to-slate-950/80 border border-slate-700/50 rounded-lg p-6 font-mono text-sm overflow-x-auto backdrop-blur-sm">
        <div className="space-y-1">
          {lines.map((line, idx) => (
            <div key={idx} className="flex gap-4">
              <span className="text-slate-600 select-none w-8 text-right flex-shrink-0">
                {idx + 1}
              </span>
              <span className="text-slate-400 flex-1 break-words">
                {line === '' ? '\u00A0' : highlightLine(line)}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Info about highlighting */}
      {highlightPhrases.length > 0 && (
        <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-lg p-4 text-xs text-yellow-300">
          <p className="flex items-center gap-2">
            <span>💡</span>
            <span>
              Highlighted phrases (<span className="font-bold">{highlightPhrases.length}</span> found) indicate suspicious content patterns detected by the ML model.
            </span>
          </p>
        </div>
      )}
    </div>
  );
}
