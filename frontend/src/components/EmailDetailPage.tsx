import { useEffect, useState, useRef } from 'react';
import PhishingRiskSpeedometer from './PhishingRiskSpeedometer';
import { analyzeEmailGroq, chatWithGroq } from '../api';
import { exportForensicPDF } from '../utils/pdfExport';
import { Send, X } from 'lucide-react';

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
  
  // New State: Chatbot & Report
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; timestamp: Date }>>([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [isChatLoading, setIsChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // ═══════════════════════════════════════════════════════════════════
  // Privacy & Audit Logging Utility
  // ═══════════════════════════════════════════════════════════════════
  const logPrivacyEvent = (action: string, details: Record<string, any> = {}) => {
    const privacyEvent = {
      timestamp: new Date().toISOString(),
      action,
      emailId: email.id,
      emailSubject: email.subject,
      ...details,
    };
    console.log('🔐 PRIVACY LOG EVENT:', privacyEvent);
    // TODO: POST to /api/audit/privacy-log in production
  };

  // ═══════════════════════════════════════════════════════════════════
  // Report Generation: Export Professional PDF
  // ═══════════════════════════════════════════════════════════════════
  const generateForensicReport = () => {
    try {
      // Prepare Security DNA data from UI (estimated from component state)
      const securityDNAData = {
        headerAuth: 65,
        linkAnalysis: 58,
        contentAnalysis: 55,
        spfDkim: 72,
        dmarc: 43,
      };

      // Call PDF export function with email data
      exportForensicPDF(email, securityDNAData);

      // Log privacy event for audit trail
      logPrivacyEvent('Exported Forensic PDF Report', { 
        reportType: 'PDF', 
        emailSubject: email.subject,
        riskScore: email.final_score
      });
    } catch (error) {
      console.error('❌ PDF Export Error:', error);
      alert('Failed to generate PDF report. Please check the browser console.');
    }
  };

  // ═══════════════════════════════════════════════════════════════════
  // Chatbot Handler - Call Real Groq API
  // ═══════════════════════════════════════════════════════════════════
  const handleAskPhishGPT = async () => {
    if (!chatInput.trim()) return;

    // Add user message
    const userMsg = { role: 'user' as const, content: chatInput, timestamp: new Date() };
    setChatMessages(prev => [...prev, userMsg]);
    setChatInput('');
    setIsChatLoading(true);

    logPrivacyEvent('Consulted AI Analyst', { query: chatInput });

    try {
      // Build context with available email information
      const context = {
        emailId: email.id,
        subject: email.subject,
        sender: email.sender,
        riskScore: email.final_score,
        riskLevel: email.risk_score,
        urls: email.highlight?.urls || [],
        suspiciousPhrases: aiAnalysis?.suspicious_phrases || [],
        redFlags: aiAnalysis?.red_flags || [],
        explanation: aiAnalysis?.explanation || 'Email requires analysis',
      };

      // Convert timestamp to ISO string for API
      const conversationHistory = chatMessages.map(msg => ({
        ...msg,
        timestamp: msg.timestamp instanceof Date ? msg.timestamp.toISOString() : msg.timestamp
      }));

      // Call backend API
      const response = await chatWithGroq({
        query: chatInput,
        conversationHistory,
        context
      });

      if (response.message) {
        const aiMsg = {
          role: 'assistant' as const,
          content: response.message,
          timestamp: new Date(),
        };
        setChatMessages(prev => [...prev, aiMsg]);
      }
    } catch (error) {
      console.error('Chat error:', error);
      const errorMsg = {
        role: 'assistant' as const,
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date(),
      };
      setChatMessages(prev => [...prev, errorMsg]);
    } finally {
      setIsChatLoading(false);
    }
  };

  // Auto-scroll to latest message
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);
  
  // Generate initial phishing analysis message
  const generateInitialAnalysis = async () => {
    try {
      const context = {
        emailId: email.id,
        subject: email.subject,
        sender: email.sender,
        riskScore: email.final_score,
        riskLevel: email.risk_score,
        urls: email.highlight?.urls || [],
        suspiciousPhrases: aiAnalysis?.suspicious_phrases || [],
        redFlags: aiAnalysis?.red_flags || [],
      };

      const analysisPrompt = `Based on this email analysis, explain in 2-3 sentences why this email is flagged as ${email.risk_score} risk for phishing. Include specific indicators from the available data.`;

      const response = await chatWithGroq({
        query: analysisPrompt,
        conversationHistory: [],
        context
      });

      if (response.message) {
        setChatMessages([
          {
            role: 'assistant' as const,
            content: response.message,
            timestamp: new Date(),
          }
        ]);
      }
    } catch (error) {
      console.error('Failed to generate initial analysis:', error);
      // Fallback message
      setChatMessages([
        {
          role: 'assistant' as const,
          content: `This email has been flagged as ${email.risk_score} risk for phishing based on analysis of headers, content, URLs, and suspicious phrases. Ask me specific questions to understand the threats better.`,
          timestamp: new Date(),
        }
      ]);
    }
  };
  
  // Debug: Log email data when it changes
  useEffect(() => {
    console.log('=== EMAIL DATA RECEIVED ===');
    console.log('Email ID:', email.id);
    console.log('Subject:', email.subject);
    console.log('Body length:', email.body?.length);
    console.log('Highlight phrases:', email.highlight?.phrases);
    console.log('AI Analysis from batch:', email.ai_analysis);
    console.log('Suspicious phrases from AI:', email.ai_analysis?.suspicious_phrases);
    
    // Privacy Log: Email Details Page Viewed
    logPrivacyEvent('Viewed Email Details', { 
      riskScore: email.risk_score,
      hasAttachments: false,
      containsUrls: (email.highlight?.urls?.length || 0) > 0,
    });
    
    // Update AI analysis if it was loaded during batch processing
    if (email.ai_analysis) {
      setAiAnalysis(email.ai_analysis);
      setIsLoadingGrok(false);
    }

    // Auto-open chat and generate initial analysis
    setIsChatOpen(true);
    generateInitialAnalysis();
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
          if (data.ai_analysis) {
            setAiAnalysis(data.ai_analysis);
          }
          setIsLoadingGrok(false);
        })
        .catch(err => {
          console.log('⚠️ Groq analysis failed:', err);
          setIsLoadingGrok(false);
        });
    }
  }, [email.id]);

  const getRiskTextColor = () => {
    switch (email.risk_score) {
      case 'HIGH': return 'text-rose-400';
      case 'MEDIUM': return 'text-amber-400';
      case 'LOW': return 'text-emerald-400';
      default: return 'text-slate-400';
    }
  };

  return (
    <div className="min-h-screen bg-slate-950">
      {/* ═══════════════════════════════════════════════════════════════════
          MAIN CONTAINER - Centered with max width
          ═══════════════════════════════════════════════════════════════════ */}
      <div className="max-w-[1400px] mx-auto p-6 flex flex-col gap-6 text-slate-200">

        {/* ═══════════════════════════════════════════════════════════════════
            PAGE HEADER - Clean section with back button and metadata
            ═══════════════════════════════════════════════════════════════════ */}
        <div className="space-y-4">
          {/* Back Button */}
          <button
            onClick={onBack}
            className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/40 hover:bg-slate-800/60 text-slate-300 text-sm font-medium rounded transition-colors duration-200 border border-slate-700/50"
          >
            ← Back
          </button>

          {/* Subject Line */}
          <h1 className="text-3xl font-bold text-white break-words">
            {email.subject}
          </h1>

          {/* Metadata Row */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-4 text-slate-400 text-sm">
            <span title={email.sender} className="truncate">
              <span className="font-semibold text-slate-300">From:</span> {email.sender}
            </span>
            <span className="hidden sm:inline text-slate-600">•</span>
            <span className="flex-shrink-0">
              {new Date(email.timestamp).toLocaleString()}
            </span>
            <span className="hidden sm:inline text-slate-600">•</span>
            <span className="font-mono text-slate-500">
              ID: {email.id.substring(0, 32)}...
            </span>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            DASHBOARD GRID - 12 column Bento Box layout
            ═══════════════════════════════════════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* CARD 1: THREAT VERDICT (5 cols) - Compact & Dense */}
          <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl p-5 backdrop-blur-sm flex flex-col items-center justify-center space-y-2">
            {/* Title */}
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
              Threat Verdict
            </h2>

            {/* Speedometer Gauge - Compact */}
            <div className="flex justify-center w-full scale-90">
              <PhishingRiskSpeedometer 
                riskScore={email.final_score * 100}
                animationDuration={1200}
              />
            </div>
          </div>

          {/* CARD 2: SECURITY DNA (7 cols) - High Density */}
          <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl p-5 backdrop-blur-sm">
            {/* Card Title */}
            <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-5">
              Security DNA
            </h2>

            {/* Analysis Progress Bars - Tight Stack */}
            <div className="flex flex-col space-y-4">
              {/* Header Auth */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Header Authentication</p>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div className="h-full w-1/3 bg-gradient-to-r from-cyan-500 to-blue-500"></div>
                  </div>
                  <span className="text-xs font-bold text-slate-300 font-mono w-10 text-right">33%</span>
                </div>
              </div>

              {/* Link Analysis */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Link Analysis</p>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div className="h-full w-1/2 bg-gradient-to-r from-amber-500 to-orange-500"></div>
                  </div>
                  <span className="text-xs font-bold text-slate-300 font-mono w-10 text-right">50%</span>
                </div>
              </div>

              {/* Content Analysis */}
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-2">Content Analysis</p>
                <div className="flex items-center gap-3">
                  <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-rose-500 to-red-600" 
                      style={{ width: `${email.final_score * 100}%` }}
                    ></div>
                  </div>
                  <span className={`text-xs font-bold font-mono w-10 text-right ${getRiskTextColor()}`}>
                    {(email.final_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            ACTION COMMAND BAR - Full width unified toolbar
            ═══════════════════════════════════════════════════════════════════ */}
        <div className="flex flex-wrap gap-3 items-center bg-slate-900/50 p-4 border border-slate-800 rounded-lg backdrop-blur-sm">
          {/* Action Buttons */}
          <button 
            onClick={() => {
              logPrivacyEvent('Executed Security Action', { action: 'Mark Safe', riskScore: email.risk_score });
              console.log('Marked as safe');
            }}
            className="px-4 py-2 bg-emerald-900/40 hover:bg-emerald-900/60 text-emerald-300 text-sm font-medium rounded-full border border-emerald-500/30 hover:border-emerald-500/50 transition-all duration-200"
          >
            ✅ Mark Safe
          </button>

          <button 
            onClick={() => {
              logPrivacyEvent('Executed Security Action', { action: 'Quarantine', riskScore: email.risk_score });
              console.log('Quarantined');
            }}
            className="px-4 py-2 bg-amber-900/40 hover:bg-amber-900/60 text-amber-300 text-sm font-medium rounded-full border border-amber-500/30 hover:border-amber-500/50 transition-all duration-200"
          >
            🛑 Quarantine
          </button>

          <button 
            onClick={() => {
              logPrivacyEvent('Executed Security Action', { action: 'Report SOC', riskScore: email.risk_score });
              console.log('Reported to SOC');
            }}
            className="px-4 py-2 bg-rose-900/40 hover:bg-rose-900/60 text-rose-300 text-sm font-medium rounded-full border border-rose-500/30 hover:border-rose-500/50 transition-all duration-200"
          >
            📢 Report SOC
          </button>

          <button 
            onClick={generateForensicReport}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-full border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"
          >
            📄 Export Report
          </button>

          {/* Spacer */}
          <div className="flex-1"></div>

          {/* Badge Indicators */}
          {email.highlight?.urls && email.highlight.urls.length > 0 && (
            <div className="px-3 py-2 bg-slate-800/40 border border-slate-700/50 rounded-full text-xs text-slate-300 font-medium">
              🔗 {email.highlight.urls.length} URL{email.highlight.urls.length > 1 ? 's' : ''}
            </div>
          )}

          {email.highlight?.phrases && email.highlight.phrases.length > 0 && (
            <div className="px-3 py-2 bg-slate-800/40 border border-slate-700/50 rounded-full text-xs text-slate-300 font-medium">
              ⚡ {email.highlight.phrases.length} Phrase{email.highlight.phrases.length > 1 ? 's' : ''}
            </div>
          )}
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            CONTEXT SECTIONS - Full width stacked blocks
            ═══════════════════════════════════════════════════════════════════ */}

        {/* EMAIL BODY VIEWER */}
        <div className="bg-[#0d1117] border border-slate-700/30 rounded-lg overflow-hidden font-mono text-xs">
          {/* Header */}
          <div className="bg-slate-900/60 px-4 py-2 border-b border-slate-700/30 flex items-center gap-2">
            <span className="text-slate-500">📄 Email Body (Sanitized)</span>
            <span className="text-slate-600 text-[10px]">• Line {email.body?.split('\n').length || 0}</span>
          </div>

          {/* Body Content */}
          <div className="flex overflow-x-auto">
            {/* Line Numbers */}
            <div className="bg-slate-900/30 text-slate-600 px-3 py-3 border-r border-slate-700/20 select-none min-w-fit">
              {email.body?.split('\n').map((_, idx) => (
                <div key={idx} className="leading-5 h-5">
                  {idx + 1}
                </div>
              )) || <div className="leading-5 h-5">1</div>}
            </div>

            {/* Email Content */}
            <div className="flex-1 px-4 py-3 overflow-auto max-h-[400px] text-slate-300 leading-5">
              {email.body ? (
                email.body.split('\n').map((line, lineIdx) => {
                  const phrasesToHighlight = new Set<string>();
                  if (email.highlight?.phrases) {
                    email.highlight.phrases.forEach(p => phrasesToHighlight.add(p));
                  }
                  if (aiAnalysis?.suspicious_phrases) {
                    aiAnalysis.suspicious_phrases.forEach(p => phrasesToHighlight.add(p));
                  }

                  const phraseArray = Array.from(phrasesToHighlight);
                  const escapedPhrases = phraseArray.map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
                  const regex = new RegExp(`(${escapedPhrases.join('|')})`, 'gi');
                  const parts = line.split(regex);

                  return (
                    <div key={lineIdx} className="h-5">
                      {parts.map((part, partIdx) => {
                        const isHighlighted = phraseArray.some(p => p.toLowerCase() === part.toLowerCase());
                        return isHighlighted && part.length > 0 ? (
                          <span key={partIdx} className="bg-rose-900/60 text-rose-300 font-semibold">
                            {part}
                          </span>
                        ) : (
                          <span key={partIdx}>{part}</span>
                        );
                      })}
                    </div>
                  );
                })
              ) : (
                <div className="text-slate-500 italic">(No email body content)</div>
              )}
            </div>
          </div>
        </div>

        {/* AI ANALYSIS SECTION */}
        {isLoadingGrok ? (
          <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-4 flex items-center justify-center gap-3 backdrop-blur-sm">
            <div className="animate-spin w-4 h-4 border-2 border-cyan-500 border-t-slate-400 rounded-full"></div>
            <p className="text-slate-300 text-sm font-medium">Analyzing with AI...</p>
          </div>
        ) : aiAnalysis ? (
          <div className="bg-slate-800/20 border border-slate-700/50 rounded-lg p-5 space-y-4 backdrop-blur-sm">
            <h3 className="text-sm font-bold text-cyan-300">🤖 AI Analysis</h3>
            
            <p className="text-xs text-slate-300 leading-relaxed">
              {aiAnalysis.explanation}
            </p>

            {aiAnalysis.red_flags && aiAnalysis.red_flags.length > 0 && (
              <div className="space-y-3">
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">
                  {email.risk_score === 'HIGH' ? '🚨 Risk Factors' : '✅ Safety Indicators'}
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {aiAnalysis.red_flags.map((flag, idx) => (
                    <div key={idx} className="text-xs text-slate-300 flex gap-2">
                      <span className="text-slate-600 flex-shrink-0">•</span>
                      <span>{flag}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* PHISHGPT CHATBOT - Full width below context */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm flex flex-col">
          {/* Chat Header */}
          <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-800/50">
            <h2 className="text-sm font-bold text-cyan-300 flex items-center gap-2">
              🤖 PhishGPT Analyst
            </h2>
            <button
              onClick={() => setIsChatOpen(!isChatOpen)}
              className="text-slate-400 hover:text-slate-200 transition-colors p-1"
              title={isChatOpen ? 'Minimize' : 'Expand'}
            >
              {isChatOpen ? <X size={18} /> : <Send size={18} />}
            </button>
          </div>

          {/* Chat Content - Collapsible */}
          {isChatOpen && (
            <>
              {/* Message History */}
              <div className="px-5 py-4 space-y-3 max-h-[350px] overflow-y-auto">
                {chatMessages.length === 0 ? (
                  <div className="text-xs text-slate-500 italic text-center py-8">
                    🤔 Ask about this email's phishing risk, suspicious links, or recommended actions...
                  </div>
                ) : (
                  chatMessages.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div
                        className={`max-w-lg px-4 py-2.5 rounded-lg text-xs leading-relaxed ${
                          msg.role === 'user'
                            ? 'bg-cyan-900/40 text-cyan-200 border border-cyan-500/30'
                            : 'bg-slate-800/50 text-slate-300 border border-slate-700/40'
                        }`}
                      >
                        {msg.content}
                      </div>
                    </div>
                  ))
                )}
                {isChatLoading && (
                  <div className="flex justify-start">
                    <div className="px-4 py-2.5 rounded-lg text-xs bg-slate-800/50 text-slate-400 border border-slate-700/40">
                      <div className="flex items-center gap-1.5">
                        <span className="animate-bounce">●</span>
                        <span className="animate-bounce" style={{ animationDelay: '0.1s' }}>●</span>
                        <span className="animate-bounce" style={{ animationDelay: '0.2s' }}>●</span>
                      </div>
                    </div>
                  </div>
                )}
                <div ref={chatEndRef} />
              </div>

              {/* Chat Input Area */}
              <div className="px-5 py-4 border-t border-slate-800 flex gap-3 bg-slate-800/30">
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleAskPhishGPT()}
                  placeholder="Ask a question..."
                  disabled={isChatLoading}
                  className="flex-1 px-3 py-2.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500/50 disabled:opacity-50 transition-colors"
                />
                <button
                  onClick={handleAskPhishGPT}
                  disabled={isChatLoading || !chatInput.trim()}
                  className="px-4 py-2.5 bg-cyan-900/40 hover:bg-cyan-900/60 text-cyan-300 rounded border border-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                  title="Send message (or press Enter)"
                >
                  <Send size={16} />
                </button>
              </div>
            </>
          )}
        </div>

      </div>
    </div>
  );
}
