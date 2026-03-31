import { useState, useEffect, useRef } from 'react';
import { Send, X, MessageSquare } from 'lucide-react';
import { appendPrivacyLog, PrivacyEventType } from '../utils/privacyLog';

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp?: string;
}

interface PhishChatBoxProps {
  selectedEmailId?: string;
  inboxStats?: Record<string, unknown>;
  flaggedCount?: number;
  onClose?: () => void;
  isOpen?: boolean;
}

/**
 * PhishChatBox Component
 * 
 * Interactive chatbot for email security Q/A.
 * - Maintains conversation history
 * - Supports contextual queries (selected email, inbox stats)
 * - Integrates with backend Groq LLM API
 * - Logs all interactions for privacy compliance
 */
export default function PhishChatBox({
  selectedEmailId,
  inboxStats,
  flaggedCount = 0,
  onClose,
  isOpen = true,
}: PhishChatBoxProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Add welcome message on mount
  useEffect(() => {
    if (messages.length === 0 && isOpen) {
      const welcomeMsg: ChatMessage = {
        role: 'assistant',
        content: 'Hello! I\'m PhishGPT, your email security assistant. Ask me about phishing risks, email analysis, or inbox security trends.',
        timestamp: new Date().toISOString(),
      };
      setMessages([welcomeMsg]);
    }
  }, [isOpen, messages.length]);

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    // Add user message to UI
    const userMsg: ChatMessage = {
      role: 'user',
      content: inputValue,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue('');
    setIsLoading(true);
    setError(null);

    try {
      // Log privacy event
      await appendPrivacyLog(
        PrivacyEventType.CHAT_QUERY,
        `Chat query: "${inputValue.substring(0, 50)}..."`,
        selectedEmailId,
        { conversationLength: messages.length }
      );

      // Call backend chat endpoint
      const response = await fetch('http://localhost:8000/api/chat-groq', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: inputValue,
          conversationHistory: messages,
          context: {
            selectedEmailId,
            inboxStats,
            flaggedCount,
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      const data = await response.json();

      // Add bot response to UI
      const botMsg: ChatMessage = {
        role: 'assistant',
        content: data.message,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Unknown error';
      setError(errorMsg);
      console.error('Chat error:', err);

      // Add error message to conversation
      const errorBotMsg: ChatMessage = {
        role: 'assistant',
        content: `Sorry, I encountered an error: ${errorMsg}. Please try again.`,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorBotMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) {
    return null;
  }

  return (
    <div className="fixed bottom-6 right-6 w-96 h-[500px] flex flex-col bg-slate-950 border border-slate-700 rounded-lg shadow-2xl z-50">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-700">
        <div className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-emerald-500" />
          <h3 className="font-bold text-white">PhishGPT Assistant</h3>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.map((msg, idx) => (
          <div
            key={idx}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-xs px-4 py-2 rounded-lg text-sm ${
                msg.role === 'user'
                  ? 'bg-emerald-600 text-white'
                  : 'bg-slate-800 text-slate-100 border border-slate-700'
              }`}
            >
              {msg.content}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-slate-800 border border-slate-700 px-4 py-2 rounded-lg text-sm text-slate-400">
              <div className="flex gap-1">
                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce" />
                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce delay-100" />
                <div className="w-2 h-2 bg-emerald-500 rounded-full animate-bounce delay-200" />
              </div>
            </div>
          </div>
        )}

        {error && (
          <div className="flex justify-start">
            <div className="bg-red-900 border border-red-700 px-4 py-2 rounded-lg text-sm text-red-100">
              {error}
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="border-t border-slate-700 p-4">
        <div className="flex gap-2">
          <input
            type="text"
            placeholder="Ask about email risks..."
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyPress={(e) => {
              if (e.key === 'Enter' && !isLoading) {
                handleSendMessage();
              }
            }}
            disabled={isLoading}
            className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 disabled:opacity-50"
          />
          <button
            onClick={handleSendMessage}
            disabled={isLoading || !inputValue.trim()}
            className="bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white px-3 py-2 rounded transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
