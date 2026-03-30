import React, { useEffect, useState } from 'react';
import RiskBadge from './RiskBadge';

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
  ai_analysis?: {
    explanation: string;
    red_flags: string[];
    ai_summary: string;
    suspicious_phrases?: string[];
    domain?: string;
    is_valid_domain?: boolean;
    highlighted_text?: string[];
    recommendation?: string;
  };
  groq_domain?: string;
  groq_is_valid_domain?: boolean;
  groq_highlighted_text?: string[];
}

interface EmailDetailPageProps {
  email: EmailData;
  onBack: () => void;
}

export default function EmailDetailPage({ email, onBack }: EmailDetailPageProps) {
  const [aiAnalysis, setAiAnalysis] = useState(email.ai_analysis);
  const [isLoadingGrok, setIsLoadingGrok] = useState(false);
  const [aiRiskScore, setAiRiskScore] = useState<number | null>(null);
  
  // Debug: Log email data when it changes
  useEffect(() => {
    console.log('=== EMAIL DATA RECEIVED ===');
    console.log('Email ID:', email.id);
    console.log('Subject:', email.subject);
    console.log('Body length:', email.body?.length);
    console.log('Highlight phrases:', email.highlight?.phrases);
    console.log('AI Analysis from batch:', email.ai_analysis);
    console.log('Suspicious phrases from AI:', email.ai_analysis?.suspicious_phrases);
    // Update AI analysis if it was loaded during batch processing
    if (email.ai_analysis) {
      setAiAnalysis(email.ai_analysis);
      setIsLoadingGrok(false);
    }
  }, [email.id]);

  // Call Groq API as fallback if batch processing didn't include analysis
  useEffect(() => {
    // Only fetch if we don't have AI analysis from batch processing
    if (!aiAnalysis && email.subject) {
      setIsLoadingGrok(true);
      console.log('📡 Fetching Groq AI analysis (fallback):', email.subject);
      
      fetch('http://localhost:8000/analyze-email-groq', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email_text: email.body || '',
          subject: email.subject,
          sender: email.sender || '',
          urls: email.highlight?.urls || []
        })
      })
        .then(res => res.json())
        .then(data => {
          console.log('✅ Groq AI analysis received:', data.ai_analysis);
          console.log('📊 Groq AI Risk Score:', data.risk_score);
          if (data.ai_analysis) {
            setAiAnalysis(data.ai_analysis);
          }
          if (data.risk_score) {
            setAiRiskScore(data.risk_score);
          }
          setIsLoadingGrok(false);
        })
        .catch(err => {
          console.log('⚠️ Groq analysis failed:', err);
          setIsLoadingGrok(false);
        });
    }
  }, [email.id]);

  // Highlight text with suspicious phrases - Fixed version
  const highlightText = (text: string, phrases: string[]): React.ReactNode => {
    if (!phrases || phrases.length === 0) return text;
    
    // Sort phrases by length (longest first) to avoid partial matches
    const sortedPhrases = [...phrases].sort((a, b) => b.length - a.length);
    
    // Create a regex that matches any of the phrases (case-insensitive)
    const escapedPhrases = sortedPhrases.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const regex = new RegExp(`(${escapedPhrases.join('|')})`, 'gi');
    
    // Split by the regex, keeping the matched phrases
    const parts = text.split(regex);
    
    return (
      <>
        {parts.map((part, idx) => {
          // Check if this part matches any phrase (case-insensitive)
          const isHighlighted = sortedPhrases.some(phrase => 
            part.toLowerCase() === phrase.toLowerCase()
          );
          
          if (isHighlighted && part.length > 0) {
            return (
              <span 
                key={idx} 
                className="bg-yellow-300 text-yellow-900 font-bold px-1 rounded inline"
              >
                {part}
              </span>
            );
          }
          return <span key={idx}>{part}</span>;
        })}
      </>
    );
  };

  // Split text into lines and render with proper spacing
  const renderEmailBody = (text: string): React.ReactNode => {
    if (!text) return '(No email body content available)';
    
    // Combine phrases from both sources for comprehensive highlighting
    const phrasesToHighlight = new Set<string>();
    
    // Add original highlight phrases
    if (email.highlight?.phrases) {
      email.highlight.phrases.forEach(phrase => phrasesToHighlight.add(phrase));
    }
    
    // Add Grok-extracted suspicious phrases (AI analysis)
    if (aiAnalysis?.suspicious_phrases) {
      aiAnalysis.suspicious_phrases.forEach(phrase => phrasesToHighlight.add(phrase));
    }
    
    const phraseArray = Array.from(phrasesToHighlight);
    
    // Debug logging
    console.log('Phrases to highlight:', phraseArray);
    console.log('Email highlight phrases:', email.highlight?.phrases);
    console.log('AI analysis suspicious phrases:', aiAnalysis?.suspicious_phrases);
    
    // Split by lines and filter empty ones
    const lines = text.split('\n').filter(line => line.trim().length > 0);
    
    return (
      <div className="space-y-2">
        {lines.map((line, idx) => {
          // Apply highlighting to this line with all suspicious phrases
          const highlightedLine = highlightText(line, phraseArray);
          
          return (
            <div key={idx} className="text-gray-900">
              {highlightedLine}
            </div>
          );
        })}
      </div>
    );
  };

  const getRiskColor = () => {
    switch (email.risk_score) {
      case 'HIGH':
        return 'from-red-900/40 to-red-800/20 border-red-500/40';
      case 'MEDIUM':
        return 'from-yellow-900/40 to-yellow-800/20 border-yellow-500/40';
      case 'LOW':
        return 'from-green-900/40 to-green-800/20 border-green-500/40';
      default:
        return 'from-slate-900/40 to-slate-800/20 border-slate-500/40';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 flex flex-col">
      {/* Background Blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0 top-32">
        <div className="absolute top-20 left-10 w-72 h-72 bg-blue-500/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 right-10 w-72 h-72 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      </div>

      {/* Main Content */}
      <div className="relative z-10 flex-1 max-w-5xl w-full mx-auto px-6 py-8">
        {/* Back Button */}
        <button
          onClick={onBack}
          className="mb-6 px-4 py-2 bg-slate-700/50 hover:bg-slate-600/50 text-blue-300 rounded-lg font-semibold transition-all duration-300 border border-slate-600/50"
        >
          ← Back to Inbox
        </button>

        {/* Email Container */}
        <div className={`bg-gradient-to-br ${getRiskColor()} border rounded-xl backdrop-blur-sm shadow-2xl overflow-hidden`}>
          {/* Header Section */}
          <div className="px-8 py-6 border-b border-slate-600/50 bg-gradient-to-r from-slate-800/80 to-slate-700/80">
            <div className="flex items-start justify-between gap-4 mb-4">
              <div className="flex-1 min-w-0">
                <h1 className="text-3xl font-bold text-white break-words mb-2">{email.subject}</h1>
                <p className="text-sm text-slate-300">
                  <span className="font-semibold text-slate-200">From:</span> {email.sender}
                </p>
              </div>
              <div className="flex-shrink-0">
                <RiskBadge risk={email.risk_score} />
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-4 gap-4 mt-6">
              <div className="bg-slate-900/70 rounded-lg p-3 border border-slate-700/50">
                <p className="text-xs text-slate-400 font-semibold uppercase mb-1">Heuristic Score</p>
                <p className={`text-2xl font-bold ${
                  email.risk_score === 'HIGH' ? 'text-red-400' :
                  email.risk_score === 'MEDIUM' ? 'text-yellow-400' :
                  'text-green-400'
                }`}>
                  {(email.final_score * 100).toFixed(0)}%
                </p>
              </div>
              {aiRiskScore !== null && (
                <div className="bg-purple-900/70 rounded-lg p-3 border-2 border-purple-500 animate-pulse">
                  <p className="text-xs text-purple-300 font-bold uppercase mb-1">🤖 AI Risk Score</p>
                  <p className={`text-2xl font-bold ${
                    aiRiskScore >= 0.75 ? 'text-red-400' :
                    aiRiskScore >= 0.50 ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>
                    {(aiRiskScore * 100).toFixed(0)}%
                  </p>
                </div>
              )}
              <div className="bg-slate-900/70 rounded-lg p-3 border border-slate-700/50">
                <p className="text-xs text-slate-400 font-semibold uppercase mb-1">Status</p>
                <p className="text-2xl font-bold text-blue-400">{email.risk_score}</p>
              </div>
              <div className="bg-slate-900/70 rounded-lg p-3 border border-slate-700/50">
                <p className="text-xs text-slate-400 font-semibold uppercase mb-1">Fetch Time</p>
                <p className="text-2xl font-bold text-emerald-400">{email.fetch_time_ms}ms</p>
              </div>
              <div className="bg-slate-900/70 rounded-lg p-3 border border-slate-700/50">
                <p className="text-xs text-slate-400 font-semibold uppercase mb-1">Analysis</p>
                <p className="text-2xl font-bold text-purple-400">{email.model_time_ms}ms</p>
              </div>
            </div>
          </div>

          {/* Body Content */}
          <div className="px-8 py-6 space-y-8">
            {/* Email Body Section - Professional Formal Email Format */}
            <div>
              <h2 className="text-2xl font-bold text-blue-300 mb-6 flex items-center gap-2">
                <span className="text-3xl">📧</span> Email Message
              </h2>
              
              {/* Email Card - Gmail/Outlook Style */}
              <div className="bg-white rounded-xl overflow-hidden shadow-2xl border border-gray-200">
                
              {/* Email Header - Professional Styling */}
                <div className="bg-gradient-to-r from-slate-50 to-gray-100 px-10 py-8 border-b-2 border-gray-300">
                  <div className="space-y-6">
                    {/* Top Row: Sender & Risk Badge */}
                    <div className="flex items-start justify-between gap-6">
                      {/* Left: Sender Info */}
                      <div className="flex items-start gap-4 flex-1">
                        <div className="flex-shrink-0">
                          <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center text-white font-bold text-2xl shadow-lg border-2 border-white">
                            {email.sender.charAt(0).toUpperCase()}
                          </div>
                        </div>
                        <div className="flex-1 min-w-0 pt-1">
                          <h3 className="text-xl font-bold text-gray-900 break-words">{email.sender}</h3>
                          <p className="text-sm text-gray-600 font-medium mt-1">to me</p>
                          <p className="text-xs text-gray-500 mt-2">
                            {new Date(email.timestamp).toLocaleDateString('en-US', {
                              year: 'numeric',
                              month: 'long',
                              day: 'numeric'
                            })} at {new Date(email.timestamp).toLocaleTimeString('en-US', {
                              hour: '2-digit',
                              minute: '2-digit'
                            })}
                          </p>
                        </div>
                      </div>

                      {/* Right: Risk Badge */}
                      <div className="flex-shrink-0">
                        <div className="bg-white rounded-xl p-4 shadow-md border-2" 
                          style={{
                            borderColor: email.risk_score === 'HIGH' ? '#ef4444' : email.risk_score === 'MEDIUM' ? '#f59e0b' : '#10b981'
                          }}>
                          <div className="text-center">
                            <p className="text-3xl mb-1">
                              {email.risk_score === 'HIGH' ? '🔴' : email.risk_score === 'MEDIUM' ? '🟡' : '🟢'}
                            </p>
                            <p className="text-xs font-bold text-gray-600 uppercase">Risk Level</p>
                            <p className={`text-lg font-bold mt-1 ${
                              email.risk_score === 'HIGH' ? 'text-red-600' : 
                              email.risk_score === 'MEDIUM' ? 'text-yellow-600' : 
                              'text-green-600'
                            }`}>{email.risk_score}</p>
                            <p className="text-xs text-gray-600 mt-2 font-semibold">{(email.final_score * 100).toFixed(0)}% Score</p>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Subject Section */}
                    <div className="border-t-2 border-gray-200 pt-6">
                      <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-2">📧 Subject</p>
                      <h2 className="text-3xl font-bold text-gray-900 break-words leading-tight">{email.subject}</h2>
                    </div>
                  </div>
                </div>

                {/* Email Body Content - Formal Format */}
                <div className="px-10 py-8 text-gray-800 bg-white min-h-96">
                  <div className="text-base leading-8 whitespace-normal font-normal" style={{ fontFamily: '"Segoe UI", Tahoma, sans-serif', color: '#333' }}>
                    {renderEmailBody(email.body)}
                  </div>
                  
                  {/* DEBUG: Show what phrases are being highlighted */}
                  <div className="mt-8 pt-4 border-t border-gray-300">
                    <p className="text-xs font-bold text-gray-600 mb-2">🔍 DEBUG - Highlighting Test:</p>
                    <div className="bg-gray-100 p-3 rounded text-xs space-y-1">
                      <p>• Email highlight phrases: {email.highlight?.phrases?.length || 0}</p>
                      <p>• AI suspicious phrases: {aiAnalysis?.suspicious_phrases?.length || 0}</p>
                      <p>• Total phrases to highlight: {(email.highlight?.phrases?.length || 0) + (aiAnalysis?.suspicious_phrases?.length || 0)}</p>
                      {email.highlight?.phrases && email.highlight.phrases.length > 0 && (
                        <div>
                          <p className="font-semibold mt-2">From email.highlight:</p>
                          {email.highlight.phrases.map((p, i) => <p key={i}>  - "{p}"</p>)}
                        </div>
                      )}
                      {email.ai_analysis?.suspicious_phrases && email.ai_analysis.suspicious_phrases.length > 0 && (
                        <div>
                          <p className="font-semibold mt-2">From AI analysis:</p>
                          {email.ai_analysis.suspicious_phrases.map((p, i) => <p key={i}>  - "{p}"</p>)}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Email Metadata Footer */}
                <div className="bg-gray-50 px-10 py-6 border-t border-gray-200 text-xs text-gray-600 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">Email Metadata</span>
                  </div>
                  <div className="grid grid-cols-2 gap-4 pt-2 text-gray-700">
                    <div>
                      <span className="opacity-70">Message ID:</span>
                      <p className="font-mono text-xs text-gray-600 break-all">{email.id}</p>
                    </div>
                    <div>
                      <span className="opacity-70">Analysis Time:</span>
                      <p className="text-gray-700">{email.model_time_ms}ms</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* 
            DETACHED: Suspicious URLs Section - Code kept but UI disabled
            TODO: Re-enable with improved URL analysis logic
            
            {email.highlight?.urls && email.highlight.urls.length > 0 && (
              <div>
                <h2 className="text-2xl font-bold text-red-400 mb-6 flex items-center gap-2">
                  <span className="text-3xl">🔗</span> Suspicious URLs ({email.highlight.urls.length})
                </h2>
                <div className="space-y-4">
                  {email.highlight.urls.map((url, i) => (
                    <div key={i} className="bg-red-50 border-2 border-red-200 rounded-xl p-6 shadow-lg hover:shadow-xl transition-shadow">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="inline-block px-3 py-1 bg-red-100 text-red-700 text-xs font-bold rounded">URL #{i + 1}</span>
                      </div>
                      <div className="bg-gray-900 text-red-400 p-4 rounded-lg font-mono text-sm break-all mb-4 overflow-x-auto">
                        {url}
                      </div>
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div className="bg-white rounded-lg p-3 border border-gray-200">
                          <p className="text-xs font-semibold text-gray-600 uppercase mb-1">Protocol</p>
                          <p className="text-sm font-bold text-gray-900">{url.match(/^[a-z]+(?=:)/)?.[0]?.toUpperCase() || 'HTTP'}</p>
                        </div>
                        <div className="bg-white rounded-lg p-3 border border-gray-200">
                          <p className="text-xs font-semibold text-gray-600 uppercase mb-1">Domain</p>
                          <p className="text-sm font-bold text-gray-900 truncate">{url.split('/')[2] || 'N/A'}</p>
                        </div>
                      </div>
                      <div className="bg-orange-50 border-l-4 border-orange-500 p-4 rounded">
                        <p className="text-sm font-bold text-orange-900 mb-2">⚠️ Security Risks Detected:</p>
                        <ul className="text-sm text-orange-800 space-y-1 ml-2">
                          <li>✗ No HTTPS encryption - credentials can be intercepted</li>
                          <li>✗ Generic domain structure - typical of phishing sites</li>
                          <li>✗ Missing SSL certificate validation</li>
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            */}

            {/* Suspicious Phrases Section - Professional Badge Style */}
            {email.highlight?.phrases && email.highlight.phrases.length > 0 && (
              <div>
                <h2 className="text-2xl font-bold text-yellow-500 mb-6 flex items-center gap-2">
                  <span className="text-3xl">⚠️</span> Suspicious Phrases ({email.highlight.phrases.length})
                </h2>
                <div className="bg-yellow-50 rounded-xl border-2 border-yellow-200 p-6 shadow-lg">
                  <div className="flex flex-wrap gap-3">
                    {email.highlight.phrases.map((phrase, i) => (
                      <span
                        key={i}
                        className="bg-yellow-200 text-yellow-900 px-4 py-2 rounded-full text-sm font-bold border-2 border-yellow-400 shadow-md hover:shadow-lg hover:scale-105 transition-all cursor-default"
                      >
                        {phrase}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* AI Analysis Section - Grok-powered insights */}
            {isLoadingGrok ? (
              <div className="bg-gradient-to-br from-purple-900/30 to-slate-900/30 border border-purple-500/40 rounded-xl p-8 flex items-center justify-center gap-4">
                <div className="animate-spin w-6 h-6 border-2 border-purple-500 border-t-purple-200 rounded-full"></div>
                <p className="text-purple-300 font-semibold">🔄 Loading AI analysis...</p>
              </div>
            ) : aiAnalysis ? (
              <div className="bg-gradient-to-br from-purple-900/30 to-slate-900/30 border border-purple-500/40 rounded-xl p-8 space-y-6">
                <h2 className="text-2xl font-bold text-purple-300 flex items-center gap-2">
                  <span className="text-3xl">🤖</span> AI-Powered Analysis (Groq)
                </h2>
                <div className="space-y-4">
                  <div className="bg-purple-900/40 px-6 py-4 rounded-lg border-l-4 border-purple-500">
                    <p className="text-lg font-bold text-purple-200 mb-3">📊 Analysis:</p>
                    <p className="text-purple-300 leading-relaxed">{aiAnalysis.explanation}</p>
                  </div>

                  {(aiAnalysis.domain || aiAnalysis.is_valid_domain !== undefined) && (
                    <div className="bg-blue-900/40 px-6 py-4 rounded-lg border-l-4 border-blue-500">
                      <p className="text-lg font-bold text-blue-200 mb-3">🌐 Domain Analysis:</p>
                      <div className="space-y-2 text-blue-300">
                        <p className="flex items-center gap-2">
                          <span className="font-semibold">Domain:</span>
                          <span className="bg-blue-900/50 px-3 py-1 rounded font-mono text-sm">{aiAnalysis.domain || 'Unknown'}</span>
                        </p>
                        <p className="flex items-center gap-2">
                          <span className="font-semibold">Valid Domain:</span>
                          <span className={`px-3 py-1 rounded font-bold ${
                            aiAnalysis.is_valid_domain 
                              ? 'bg-green-900/50 text-green-300' 
                              : 'bg-red-900/50 text-red-300'
                          }`}>
                            {aiAnalysis.is_valid_domain ? '✅ Yes' : '❌ No / Suspicious'}
                          </span>
                        </p>
                      </div>
                    </div>
                  )}

                  {aiAnalysis.highlighted_text && aiAnalysis.highlighted_text.length > 0 && (
                    <div className="bg-yellow-900/40 px-6 py-4 rounded-lg border-l-4 border-yellow-500">
                      <p className="text-lg font-bold text-yellow-200 mb-3">🎯 Highlighted Suspicious Text:</p>
                      <div className="space-y-2 text-yellow-300">
                        {aiAnalysis.highlighted_text.map((text, idx) => (
                          <p key={idx} className="bg-yellow-900/60 px-3 py-2 rounded text-sm italic font-mono">
                            "{text}"
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {aiAnalysis.red_flags && aiAnalysis.red_flags.length > 0 && (
                    <div className={`border-l-4 p-6 rounded-xl ${
                      email.risk_score === 'HIGH' || email.risk_score === 'MEDIUM'
                        ? 'bg-red-900/30 border-red-500 text-red-200'
                        : 'bg-green-900/30 border-green-500 text-green-200'
                    }`}>
                      <p className="text-lg font-bold mb-3">
                        {email.risk_score === 'HIGH' || email.risk_score === 'MEDIUM' ? '🚨 Key Risk Factors:' : '✅ Safety Indicators:'}
                      </p>
                      <ul className="space-y-2">
                        {aiAnalysis.red_flags.map((flag, idx) => (
                          <li key={idx} className="flex items-start gap-2">
                            <span className="font-bold">
                              {email.risk_score === 'HIGH' || email.risk_score === 'MEDIUM' ? '⚠️' : '✓'}
                            </span>
                            <span>{flag}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className={`border-l-4 p-6 rounded-xl ${
                    email.risk_score === 'HIGH' || email.risk_score === 'MEDIUM'
                      ? 'bg-orange-900/30 border-orange-500 text-orange-200'
                      : 'bg-blue-900/30 border-blue-500 text-blue-200'
                  }`}>
                    <p className="text-lg font-bold mb-3">💡 Recommendation:</p>
                    <p className="leading-relaxed font-semibold">{aiAnalysis.recommendation || aiAnalysis.ai_summary || 'Review this email carefully'}</p>
                  </div>
                </div>
              </div>
            ) : null}
            
            {/* 
            DISABLED: Old Phishing Analysis Section - Now using Grok as primary source
            This section showed contradictory warnings that conflicted with Grok's verdict.
            Since Grok is 70% of the final score, we trust its analysis instead.
            
            {(email.risk_score === 'HIGH' || email.risk_score === 'MEDIUM') ? (
              <div>
                <h2 className="text-2xl font-bold text-red-600 mb-6 flex items-center gap-2">
                  <span className="text-3xl">⚠️</span> Phishing Analysis & Risk Assessment
                </h2>
                <div className="space-y-4">
                  <div className="bg-red-50 border-l-4 border-red-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-red-900 mb-3">🎯 What Makes This Email Suspicious:</p>
                    <ul className="space-y-2 text-red-800">
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">✓</span>
                        <span>Phishing intent detection triggered by machine learning model</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">✓</span>
                        <span>Suspicious URL patterns detected in email body</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">✓</span>
                        <span>Urgent action language typical of phishing campaigns</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">✓</span>
                        <span>Credential harvest indicators present</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">✓</span>
                        <span>Domain reputation concerns detected</span>
                      </li>
                    </ul>
                  </div>

                  <div className="bg-orange-50 border-l-4 border-orange-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-orange-900 mb-3">🚨 Critical Risk Indicators:</p>
                    <ul className="space-y-2 text-orange-800">
                      <li className="flex items-start gap-2">
                        <span className="text-orange-600 font-bold">⚠️</span>
                        <span>Email contains deceptive URLs designed to harvest credentials</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-orange-600 font-bold">⚠️</span>
                        <span>Sender domain may not match the organization it impersonates</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-orange-600 font-bold">⚠️</span>
                        <span>Content uses urgency and fear tactics to drive user action</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-orange-600 font-bold">⚠️</span>
                        <span>Links may redirect through multiple servers (obfuscation technology)</span>
                      </li>
                    </ul>
                  </div>

                  <div className="bg-red-100 border-2 border-red-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-red-900 mb-3">🛑 Recommended Actions:</p>
                    <ul className="space-y-2 text-red-800">
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">→</span>
                        <span className="font-semibold">Do NOT click any links or download attachments</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">→</span>
                        <span className="font-semibold">Do NOT provide personal information or credentials</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">→</span>
                        <span className="font-semibold">Report this email to your IT security team immediately</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-red-600 font-bold">→</span>
                        <span className="font-semibold">Move to spam/trash folder and empty your trash</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <h2 className="text-2xl font-bold text-green-600 mb-6 flex items-center gap-2">
                  <span className="text-3xl">✓</span> Email Safety Assessment
                </h2>
                <div className="space-y-4">
                  <div className="bg-green-50 border-l-4 border-green-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-green-900 mb-3">✅ This Email Appears Legitimate:</p>
                    <ul className="space-y-2 text-green-800">
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>No phishing intent detected by machine learning model</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>URLs and sender information appear legitimate</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>No suspicious credential harvest patterns detected</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>Email content lacks urgency or fear-based language</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">✓</span>
                        <span>Sender domain and organization match appropriately</span>
                      </li>
                    </ul>
                  </div>

                  <div className="bg-blue-50 border-l-4 border-blue-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-blue-900 mb-3">💡 Safety Indicators Present:</p>
                    <ul className="space-y-2 text-blue-800">
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">✓</span>
                        <span>Professional sender domain verified</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">✓</span>
                        <span>Email contains proper authentication headers</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">✓</span>
                        <span>Content aligns with sender's organizational purpose</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold">✓</span>
                        <span>No obfuscation or redirect techniques detected</span>
                      </li>
                    </ul>
                  </div>

                  <div className="bg-green-100 border-2 border-green-600 p-6 rounded-xl shadow-lg">
                    <p className="text-lg font-bold text-green-900 mb-3">✅ Recommended Actions:</p>
                    <ul className="space-y-2 text-green-800">
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">→</span>
                        <span>You may safely interact with this email</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">→</span>
                        <span>Links and attachments appear to be from a trusted source</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">→</span>
                        <span>Always use caution with unsolicited requests for sensitive information</span>
                      </li>
                      <li className="flex items-start gap-2">
                        <span className="text-green-600 font-bold">→</span>
                        <span>When in doubt, contact the sender directly through official channels</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Metadata */}
            <div className="border-t border-slate-600/50 pt-6 text-xs text-slate-400 space-y-1">
              <p>📅 Timestamp: {new Date(email.timestamp).toLocaleString()}</p>
              <p>🔍 Email ID: {email.id}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
