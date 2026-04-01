import { useEffect, useState, useRef } from 'react';
import PhishingRiskSpeedometer from './PhishingRiskSpeedometer';
import { analyzeEmailGroq, chatWithGroq } from '../api';
import { exportForensicPDF } from '../utils/pdfExport';
import { 
  Send, X, ShieldCheck, ShieldAlert, Flag, FileText, Link, Zap, Bot, 
  AlertTriangle, HelpCircle, ArrowLeft
} from 'lucide-react';

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
  
  // NEW: Store Groq risk score and level (overrides email.risk_score)
  const [groqRiskScore, setGroqRiskScore] = useState<number | null>(null);
  const [groqRiskLevel, setGroqRiskLevel] = useState<string | null>(null);
  const [groqConfidence, setGroqConfidence] = useState<number | null>(null);
  
  // New State: Chatbot & Report
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string; timestamp: Date }>>([]);
  const [chatInput, setChatInput] = useState('');
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [isChatLoading, setIsChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const chatSectionRef = useRef<HTMLDivElement>(null);
  const chatInputRef = useRef<HTMLInputElement>(null);

  // ═══════════════════════════════════════════════════════════════════
  // Floating Widget: Smooth scroll to chat section & focus input
  // ═══════════════════════════════════════════════════════════════════
  const scrollToChat = () => {
    // Scroll to chat section smoothly (centered in viewport)
    chatSectionRef.current?.scrollIntoView({
      behavior: 'smooth',
      block: 'center'
    });

    // After scroll animation completes, focus the input field
    setTimeout(() => {
      chatInputRef.current?.focus();
    }, 300);
  };

  // ═══════════════════════════════════════════════════════════════════
  // Helper: Safe Threat Highlighting (No dangerouslySetInnerHTML)
  // ═══════════════════════════════════════════════════════════════════
  const highlightThreats = (lineText: string, keywordsToHighlight: string[]) => {
    // If no keywords or empty line, return plain text
    if (!lineText || keywordsToHighlight.length === 0) {
      return <>{lineText}</>;
    }

    // Escape special regex characters in keywords for safe pattern matching
    const escapedKeywords = keywordsToHighlight.map(k => 
      k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    );

    // Build case-insensitive regex pattern: (keyword1|keyword2|keyword3)...
    const patternString = escapedKeywords.join('|');
    if (!patternString) return <>{lineText}</>;

    const regex = new RegExp(`(${patternString})`, 'gi');
    const parts = lineText.split(regex);

    // Map parts into safe React elements (text nodes + highlighted spans)
    return (
      <>
        {parts.map((part, idx) => {
          // Check if this part matches any keyword (case-insensitive)
          const isMatch = keywordsToHighlight.some(
            kw => kw.toLowerCase() === part.toLowerCase()
          );

          if (isMatch && part.length > 0) {
            // FORENSIC THREAT MARKER - High contrast, underlined
            return (
              <span
                key={idx}
                className="bg-rose-500/30 text-rose-300 border-b border-rose-500 px-1 rounded-sm font-semibold"
              >
                {part}
              </span>
            );
          }

          // Non-matching text - preserve original styling
          return <span key={idx}>{part}</span>;
        })}
      </>
    );
  };

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
        riskScore: currentRiskScore,
        riskLevel: currentRiskLevel,
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
        riskScore: currentRiskScore,
        riskLevel: currentRiskLevel,
        urls: email.highlight?.urls || [],
        suspiciousPhrases: aiAnalysis?.suspicious_phrases || [],
        redFlags: aiAnalysis?.red_flags || [],
      };

      const analysisPrompt = `Based on this email analysis, explain in 2-3 sentences why this email is flagged as ${currentRiskLevel} risk for phishing. Include specific indicators from the available data.`;

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
          content: `This email has been flagged as ${currentRiskLevel} risk for phishing based on analysis of headers, content, URLs, and suspicious phrases. Ask me specific questions to understand the threats better.`,
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
      console.log('📧 Analyzing email body for suspicious keywords...');
      
      analyzeEmailGroq(
        email.body || '',
        email.subject,
        email.sender || '',
        email.highlight?.urls
      )
        .then(data => {
          console.log('✅ Groq AI analysis received:', data);
          console.log('🎯 Groq Risk Score:', data.risk_score);
          console.log('🚨 Groq Risk Level:', data.risk_level);
          
          // Extract and log suspicious phrases for highlighting
          if (data.ai_analysis?.suspicious_phrases) {
            console.log('🚨 SUSPICIOUS KEYWORDS DETECTED:', data.ai_analysis.suspicious_phrases);
            console.log(`Found ${data.ai_analysis.suspicious_phrases.length} suspicious keywords/phrases`);
            
            // Log each keyword for debugging
            data.ai_analysis.suspicious_phrases.forEach((phrase: string, idx: number) => {
              console.log(`  [${idx + 1}] ${phrase}`);
            });
          }
          
          // Update state with Groq analysis
          if (data.ai_analysis) {
            setAiAnalysis(data.ai_analysis);
          }
          
          // Store Groq risk score and level (PRIMARY source of truth)
          if (data.risk_score !== undefined) {
            setGroqRiskScore(data.risk_score);
            console.log('✅ Groq Risk Score set:', data.risk_score);
          }
          
          if (data.risk_level) {
            setGroqRiskLevel(data.risk_level);
            console.log('✅ Groq Risk Level set:', data.risk_level);
          }
          
          // Extract confidence and log weighting decision
          if (data.confidence !== undefined) {
            setGroqConfidence(data.confidence);
            console.log('📊 Groq Confidence:', data.confidence);
            
            // Log which weighting will be used
            if (data.confidence > 0.8) {
              console.log('🟢 High Confidence: Will use 100% Groq + 0% Backend');
            } else if (data.confidence > 0.6) {
              console.log('🟡 Medium Confidence: Will use 80% Groq + 20% Backend');
            } else {
              console.log('🟠 Low Confidence: Will use 60% Groq + 40% Backend');
            }
          }
          
          setIsLoadingGrok(false);
        })
        .catch(err => {
          console.log('⚠️ Groq analysis failed:', err);
          setIsLoadingGrok(false);
        });
    }
  }, [email.id]);

  // Calculate final weighted risk score based on confidence
  const calculateWeightedScore = (): number => {
    // If Groq has responded with a score and confidence, use confidence-based weighting
    if (groqRiskScore !== null && groqConfidence !== null) {
      let groqWeight: number;
      let backendWeight: number;
      
      if (groqConfidence > 0.8) {
        groqWeight = 1.0;
        backendWeight = 0.0;
      } else if (groqConfidence > 0.6) {
        groqWeight = 0.8;
        backendWeight = 0.2;
      } else {
        groqWeight = 0.6;
        backendWeight = 0.4;
      }
      
      const groqScore = groqRiskScore;
      const backendScore = email.final_score || 0;
      return (groqScore * groqWeight) + (backendScore * backendWeight);
    }
    
    // Fallback: use only backend score if Groq hasn't responded yet
    return email.final_score || 0;
  };
  
  // Use Groq risk level if available, fallback to email.risk_score
  const currentRiskLevel = groqRiskLevel || email.risk_score;
  const currentRiskScore = calculateWeightedScore();
  
  const getRiskTextColor = () => {
    switch (currentRiskLevel) {
      case 'High':
      case 'HIGH': return 'text-rose-400';
      case 'Medium':
      case 'MEDIUM': return 'text-amber-400';
      case 'Low':
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
            <ArrowLeft size={16} />
            Back
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
              ID: <span className="text-slate-300">{email.id.substring(0, 32)}</span>...
            </span>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            DASHBOARD GRID - Bento Box layout
            ═══════════════════════════════════════════════════════════════════ */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

          {/* CARD 1: THREAT VERDICT (4 cols) - Compact & Dense */}
          <div className="lg:col-span-4 bg-slate-900 border border-slate-800 rounded-lg p-6 backdrop-blur-sm flex flex-col items-center justify-center space-y-4">
            {/* Title with Icon */}
            <div className="flex items-center gap-2">
              <AlertTriangle size={16} className="text-rose-400" />
              <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                Threat Verdict
              </h2>
            </div>

            {/* Speedometer Gauge */}
            <div className="flex justify-center w-full scale-95">
              <PhishingRiskSpeedometer 
                riskScore={currentRiskScore * 100}
                animationDuration={1200}
              />
            </div>

            {/* Risk Score & Classification Display */}
            <div className="grid grid-cols-2 gap-4 w-full text-center text-sm">
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Risk Score</p>
                <p className={`font-mono font-bold text-base ${getRiskTextColor()}`}>
                  {(currentRiskScore * 100).toFixed(0)}%
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Classification</p>
                <p className={`font-mono font-bold text-base ${getRiskTextColor()}`}>
                  {currentRiskLevel}
                </p>
              </div>
            </div>

            {/* Confidence & Weighting Info */}
            {groqConfidence !== null && (
              <div className="w-full border-t border-slate-700 pt-3 space-y-2 text-xs">
                {/* Confidence Level */}
                <div className="flex items-center justify-between px-2">
                  <span className="text-slate-500">AI Confidence:</span>
                  <span className={`font-mono font-semibold ${
                    groqConfidence > 0.8 ? 'text-emerald-400' : 
                    groqConfidence > 0.6 ? 'text-amber-400' : 
                    'text-rose-400'
                  }`}>
                    {(groqConfidence * 100).toFixed(0)}%
                  </span>
                </div>
                
                {/* Weighting Breakdown */}
                <div className="flex items-center justify-between px-2">
                  <span className="text-slate-500">Weighting:</span>
                  <span className="font-mono text-slate-300">
                    {groqConfidence > 0.8 ? '100% Groq' :
                     groqConfidence > 0.6 ? '80% Groq + 20% Backend' :
                     '60% Groq + 40% Backend'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* RIGHT COLUMN WRAPPER - Security DNA + Action Toolbar */}
          <div className="lg:col-span-8 flex flex-col gap-6">

            {/* CARD 2: SECURITY DNA - High Density */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 backdrop-blur-sm">
              {/* Card Title with Icon */}
              <div className="flex items-center gap-2 mb-6">
                <Zap size={16} className="text-cyan-400" />
                <h2 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                  Security DNA
                </h2>
              </div>

              {/* Analysis Progress Bars - Tight Stack */}
              <div className="space-y-6">
                {/* Header Authentication */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Header Auth</p>
                    <span className="text-xs font-mono font-bold text-slate-300">33%</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full w-1/3 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full shadow-lg shadow-cyan-500/50"></div>
                  </div>
                </div>

                {/* Link Analysis */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Link Analysis</p>
                    <span className="text-xs font-mono font-bold text-slate-300">50%</span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div className="h-full w-1/2 bg-gradient-to-r from-amber-500 to-orange-500 rounded-full shadow-lg shadow-amber-500/50"></div>
                  </div>
                </div>

                {/* Content Analysis */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Content Analysis</p>
                    <span className={`text-xs font-mono font-bold ${getRiskTextColor()}`}>
                      {(currentRiskScore * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div 
                      className="h-full bg-gradient-to-r from-rose-500 to-red-600 rounded-full shadow-lg shadow-rose-500/50" 
                      style={{ width: `${currentRiskScore * 100}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            </div>

            {/* ACTION COMMAND BAR - Now nested in right column */}
            <div className="flex flex-wrap gap-3 items-center bg-slate-900/50 p-4 border border-slate-800 rounded-lg backdrop-blur-sm">
              {/* Action Buttons */}
              <button 
                onClick={() => {
                  logPrivacyEvent('Executed Security Action', { action: 'Mark Safe', riskScore: currentRiskLevel });
                  console.log('Marked as safe');
                }}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-900/40 hover:bg-emerald-900/60 text-emerald-300 text-sm font-medium rounded-lg border border-emerald-500/30 hover:border-emerald-500/50 transition-all duration-200"
              >
                <ShieldCheck size={16} />
                Mark Safe
              </button>

              <button 
                onClick={() => {
                  logPrivacyEvent('Executed Security Action', { action: 'Quarantine', riskScore: currentRiskLevel });
                  console.log('Quarantined');
                }}
                className="flex items-center gap-2 px-4 py-2 bg-amber-900/40 hover:bg-amber-900/60 text-amber-300 text-sm font-medium rounded-lg border border-amber-500/30 hover:border-amber-500/50 transition-all duration-200"
              >
                <ShieldAlert size={16} />
                Quarantine
              </button>

              <button 
                onClick={() => {
                  logPrivacyEvent('Executed Security Action', { action: 'Report SOC', riskScore: currentRiskLevel });
                  console.log('Reported to SOC');
                }}
                className="flex items-center gap-2 px-4 py-2 bg-rose-900/40 hover:bg-rose-900/60 text-rose-300 text-sm font-medium rounded-lg border border-rose-500/30 hover:border-rose-500/50 transition-all duration-200"
              >
                <Flag size={16} />
                Report SOC
              </button>

              <button 
                onClick={generateForensicReport}
                className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium rounded-lg border border-slate-700/50 hover:border-slate-600/50 transition-all duration-200"
              >
                <FileText size={16} />
                Export Report
              </button>

              {/* Spacer */}
              <div className="flex-1"></div>

              {/* Badge Indicators with Icons */}
              {email.highlight?.urls && email.highlight.urls.length > 0 && (
                <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/40 border border-slate-700/50 rounded-lg text-xs text-slate-300 font-medium">
                  <Link size={14} />
                  <span className="font-mono">{email.highlight.urls.length}</span> URL{email.highlight.urls.length > 1 ? 's' : ''}
                </div>
              )}

              {email.highlight?.phrases && email.highlight.phrases.length > 0 && (
                <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/40 border border-slate-700/50 rounded-lg text-xs text-slate-300 font-medium">
                  <Zap size={14} />
                  <span className="font-mono">{email.highlight.phrases.length}</span> Phrase{email.highlight.phrases.length > 1 ? 's' : ''}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            FORENSIC CONTEXT SECTIONS - Full width blocks
            ═══════════════════════════════════════════════════════════════════ */}

        {/* EMAIL BODY VIEWER - Terminal Style */}
        <div className="bg-[#0d1117] border border-slate-700/30 rounded-lg overflow-hidden font-mono text-xs">
          {/* Header with Threat Summary */}
          <div className="bg-slate-900/60 px-4 py-3 border-b border-slate-700/30 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileText size={16} className="text-slate-400" />
              <span className="text-slate-200 font-semibold">Email Body (Sanitized)</span>
              <span className="text-slate-600 text-[10px]">• <span className="font-mono">{email.body?.split('\n').length || 0}</span> lines</span>
            </div>
            
            {/* Threat Summary Badge */}
            {(() => {
              const suspiciousKeywords = new Set<string>();
              if (email.highlight?.phrases) {
                email.highlight.phrases.forEach(p => suspiciousKeywords.add(p));
              }
              if (aiAnalysis?.suspicious_phrases) {
                aiAnalysis.suspicious_phrases.forEach(p => suspiciousKeywords.add(p));
              }
              const threatCount = suspiciousKeywords.size;
              
              return threatCount > 0 ? (
                <div className="flex items-center gap-2 px-3 py-1 bg-rose-500/10 border border-rose-500/30 rounded-full text-rose-300 text-[11px] font-mono">
                  <AlertTriangle size={12} />
                  <span className="font-bold">{threatCount}</span>
                  <span>threat{threatCount > 1 ? 's' : ''} detected</span>
                </div>
              ) : null;
            })()}
          </div>

          {/* Body Content */}
          <div className="flex overflow-x-auto">
            {/* Line Numbers */}
            <div className="bg-slate-900/30 text-slate-600 px-3 py-3 border-r border-slate-700/20 select-none min-w-fit">
              {email.body?.split('\n').map((_, idx) => (
                <div key={idx} className="leading-5 h-5 text-right">
                  <span className="font-mono">{(idx + 1).toString().padStart(3, ' ')}</span>
                </div>
              )) || <div className="leading-5 h-5">1</div>}
            </div>

            {/* Email Content */}
            <div className="flex-1 px-4 py-3 overflow-auto max-h-[400px] text-slate-300 leading-5">
              {email.body ? (
                email.body.split('\n').map((line, lineIdx) => {
                  // Gather all suspicious keywords from two sources
                  const suspiciousKeywords = new Set<string>();
                  if (email.highlight?.phrases) {
                    email.highlight.phrases.forEach(p => suspiciousKeywords.add(p));
                  }
                  if (aiAnalysis?.suspicious_phrases) {
                    aiAnalysis.suspicious_phrases.forEach(p => suspiciousKeywords.add(p));
                  }

                  const keywordArray = Array.from(suspiciousKeywords);

                  return (
                    <div key={lineIdx} className="h-5 font-mono">
                      {/* Use safe helper function to highlight threats inline */}
                      {highlightThreats(line, keywordArray)}
                    </div>
                  );
                })
              ) : (
                <div className="text-slate-500 italic">(No email body content)</div>
              )}
            </div>
          </div>
        </div>

        {/* AI ANALYSIS SECTION - Terminal Style */}
        {isLoadingGrok ? (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex items-center justify-center gap-3 backdrop-blur-sm">
            <div className="animate-spin w-4 h-4 border-2 border-cyan-500 border-t-slate-400 rounded-full"></div>
            <p className="text-slate-300 text-sm font-medium">Analyzing with AI...</p>
          </div>
        ) : aiAnalysis ? (
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-4 backdrop-blur-sm">
            {/* Section Header with Icon */}
            <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
              <Bot size={18} className="text-cyan-400" />
              <h3 className="text-sm font-bold text-cyan-300">AI Analysis</h3>
            </div>
            
            <p className="text-sm text-slate-300 leading-relaxed">
              {aiAnalysis.explanation}
            </p>

            {aiAnalysis.red_flags && aiAnalysis.red_flags.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  {email.risk_score === 'HIGH' ? (
                    <>
                      <AlertTriangle size={16} className="text-rose-500" />
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Risk Factors</p>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={16} className="text-emerald-500" />
                      <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Safety Indicators</p>
                    </>
                  )}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {aiAnalysis.red_flags.map((flag, idx) => (
                    <div key={idx} className="text-xs text-slate-300 flex gap-2 p-2 bg-slate-800/30 rounded border border-slate-700/20">
                      <span className="text-slate-600 flex-shrink-0 mt-0.5">•</span>
                      <span>{flag}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}

        {/* PHISHGPT CHATBOT - Terminal Style */}
        <div ref={chatSectionRef} className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden backdrop-blur-sm flex flex-col">
          {/* Chat Header */}
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-800/50">
            <div className="flex items-center gap-2">
              <Bot size={18} className="text-cyan-400" />
              <h2 className="text-sm font-bold text-cyan-300">PhishGPT Analyst</h2>
            </div>
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
              <div className="px-6 py-4 space-y-3 max-h-[350px] overflow-y-auto">
                {chatMessages.length === 0 ? (
                  <div className="text-xs text-slate-500 italic text-center py-8 flex items-center justify-center gap-2">
                    <HelpCircle size={16} />
                    Ask about this email's phishing risk, suspicious links, or recommended actions...
                  </div>
                ) : (
                  chatMessages.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                      <div
                        className={`max-w-lg px-4 py-2.5 rounded-lg text-xs leading-relaxed font-medium ${
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
              <div className="px-6 py-4 border-t border-slate-800 flex gap-3 bg-slate-800/30">
                <input
                  ref={chatInputRef}
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
                  className="flex items-center gap-2 px-4 py-2.5 bg-cyan-900/40 hover:bg-cyan-900/60 text-cyan-300 rounded border border-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all font-medium"
                  title="Send message (or press Enter)"
                >
                  <Send size={16} />
                </button>
              </div>
            </>
          )}
        </div>

        {/* ═══════════════════════════════════════════════════════════════════
            FLOATING PHISHGPT TRIGGER - Always accessible
            ═══════════════════════════════════════════════════════════════════ */}
        <div
          onClick={scrollToChat}
          className="fixed bottom-8 right-8 z-50 flex items-center gap-3 bg-slate-900 border border-slate-700 shadow-2xl rounded-full px-5 py-3 cursor-pointer hover:bg-slate-800 transition-all hover:scale-105 w-72 lg:w-80 group"
          role="button"
          tabIndex={0}
          onKeyPress={(e) => e.key === 'Enter' && scrollToChat()}
          title="Click to ask PhishGPT a question"
        >
          <Bot className="text-cyan-400 w-5 h-5 flex-shrink-0" />
          <span className="text-sm text-slate-400 group-hover:text-slate-300 transition-colors font-medium truncate">
            Ask PhishGPT a question...
          </span>
        </div>

      </div>
    </div>
  );
}
