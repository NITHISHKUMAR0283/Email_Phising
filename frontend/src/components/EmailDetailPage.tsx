import React, { useEffect, useState } from 'react';
import RiskBadge from './RiskBadge';
import RiskGauge from './RiskGauge';
import SecurityDNA from './SecurityDNA';
import SanitizedURL from './SanitizedURL';
import ActionButtons from './ActionButtons';
import SyntaxHighlightedEmail from './SyntaxHighlightedEmail';
import { analyzeEmailGroq } from '../api';

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
      
      analyzeEmailGroq(
        email.body || '',
        email.subject,
        email.sender || '',
        email.highlight?.urls
      )
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
        return 'from-red-900/35 to-red-800/25 border-red-500/50';
      case 'MEDIUM':
        return 'from-yellow-900/35 to-yellow-800/25 border-yellow-500/50';
      case 'LOW':
        return 'from-green-900/35 to-green-800/25 border-green-500/50';
      default:
        return 'from-slate-900/35 to-slate-800/25 border-slate-500/50';
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex flex-col overflow-hidden relative">
      {/* Animated Background Blobs - Dynamic Moving Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        {/* Main gradient background */}
        <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-blue-950/30 to-slate-950"></div>
        
        {/* Animated glowing orbs */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-red-500/15 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-blue-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
        <div className="absolute bottom-0 left-1/2 w-72 h-72 bg-purple-500/15 rounded-full blur-3xl animate-pulse" style={{animationDelay: '2s'}}></div>
        <div className="absolute bottom-1/4 right-0 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1.5s'}}></div>
        
        {/* Grid overlay for depth */}
        <div className="absolute inset-0 opacity-[0.02]" style={{
          backgroundImage: 'linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(0deg, rgba(255,255,255,0.1) 1px, transparent 1px)',
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      {/* Main Content */}
      <div className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {/* Back Button */}
        <button
          onClick={onBack}
          className="mb-8 px-6 py-3 bg-gradient-to-r from-slate-700/60 to-slate-600/60 hover:from-slate-700/80 hover:to-slate-600/80 text-cyan-300 rounded-lg font-semibold transition-all duration-300 border border-slate-600/50 backdrop-blur-sm shadow-lg hover:shadow-cyan-500/20"
        >
          ← Back to Inbox
        </button>

        {/* Professional Bento-Style Grid Layout */}
        <div className="grid grid-cols-3 gap-6 mb-8">
          {/* Left Column - Risk Gauge (Large) */}
          <div className="col-span-1 bg-gradient-to-br from-slate-900/40 to-slate-950/40 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
            <RiskGauge score={email.final_score} size={180} showLabel={true} />
          </div>

          {/* Middle Column - Email Header */}
          <div className="col-span-2 bg-gradient-to-br from-slate-800/50 to-slate-900/40 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
            <h1 className="text-2xl font-bold text-white break-words mb-3 line-clamp-2">{email.subject}</h1>
            <p className="text-slate-300 mb-4">
              <span className="font-semibold text-slate-200">From:</span> {email.sender}
            </p>
            <div className="flex items-center gap-3 mb-4">
              <span className={`px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wide ${
                email.risk_score === 'HIGH' ? 'bg-red-900/40 text-red-300 border border-red-500/50' :
                email.risk_score === 'MEDIUM' ? 'bg-yellow-900/40 text-yellow-300 border border-yellow-500/50' :
                'bg-green-900/40 text-green-300 border border-green-500/50'
              }`}>
                {email.risk_score === 'HIGH' ? '🚨 CRITICAL' :
                 email.risk_score === 'MEDIUM' ? '⚠️ WARNING' :
                 '✅ SAFE'}
              </span>
              <span className="text-xs text-slate-400">
                📅 {new Date(email.timestamp).toLocaleString()}
              </span>
            </div>
            <div className="text-sm text-slate-400">
              <p>ID: <span className="font-mono">{email.id.substring(0, 32)}...</span></p>
            </div>
          </div>
        </div>

        {/* Security DNA Analysis */}
        <div className="mb-8 bg-gradient-to-br from-slate-800/40 to-slate-900/30 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
          <SecurityDNA 
            headerScore={Math.random() * 0.8} 
            linkScore={Math.random() * 0.8}
            contentScore={email.final_score}
          />
        </div>

        {/* URLs and Actions Row */}
        <div className="grid grid-cols-2 gap-6 mb-8">
          {/* Sanitized URLs */}
          {email.highlight?.urls && email.highlight.urls.length > 0 && (
            <div className="bg-gradient-to-br from-slate-800/40 to-slate-900/30 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
              <SanitizedURL urls={email.highlight.urls} />
            </div>
          )}

          {/* Action Buttons */}
          <div className="bg-gradient-to-br from-slate-800/40 to-slate-900/30 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
            <ActionButtons 
              riskScore={email.final_score}
              onMarkSafe={() => console.log('Marked as safe')}
              onQuarantine={() => console.log('Quarantined')}
              onReport={() => console.log('Reported to SOC')}
            />
          </div>
        </div>

        {/* Syntax Highlighted Email Body */}
        <div className="mb-8 bg-gradient-to-br from-slate-800/40 to-slate-900/30 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-xl hover:border-slate-600/80 transition-all duration-300">
          <SyntaxHighlightedEmail 
            body={email.body} 
            highlightPhrases={email.highlight?.phrases || email.ai_analysis?.suspicious_phrases || []}
          />
        </div>

        {/* AI Analysis Section */}
        {isLoadingGrok ? (
          <div className="bg-gradient-to-br from-purple-900/30 to-slate-900/30 border-2 border-purple-500/40 rounded-2xl p-8 flex items-center justify-center gap-4 backdrop-blur-sm">
            <div className="animate-spin w-6 h-6 border-2 border-purple-500 border-t-purple-200 rounded-full"></div>
            <p className="text-purple-300 font-semibold">🔄 Loading AI analysis...</p>
          </div>
        ) : aiAnalysis ? (
          <div className="bg-gradient-to-br from-purple-900/25 to-slate-900/25 border-2 border-purple-500/40 rounded-2xl p-8 space-y-6 backdrop-blur-sm">
            <h2 className="text-2xl font-bold text-purple-300 flex items-center gap-2">
              <span className="text-3xl">🤖</span> AI-Powered Deep Dive Analysis
            </h2>
            <div className="space-y-4">
              <div className="bg-purple-900/40 px-6 py-4 rounded-lg border-l-4 border-purple-500 backdrop-blur-sm">
                <p className="text-lg font-bold text-purple-200 mb-3">📊 Analysis Summary:</p>
                <p className="text-purple-300 leading-relaxed">{aiAnalysis.explanation}</p>
              </div>

              {aiAnalysis.red_flags && aiAnalysis.red_flags.length > 0 && (
                <div className={`border-l-4 p-6 rounded-xl backdrop-blur-sm ${
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
                        <span className="mt-1">•</span>
                        <span>{flag}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
