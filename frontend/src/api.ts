// API configuration for PhishGuard AI frontend

// Determine API base URL based on environment
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Analyze email endpoint (fast analysis without Grok)
export async function analyzeEmail(email_text: string, sender?: string, urls?: string[], headers?: Record<string, string>) {
  const endpoint = `${API_BASE_URL}/analyze-email`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email_text, sender, urls, headers })
  });
  if (!res.ok) throw new Error('Failed to analyze email');
  return res.json();
}

// Analyze email with Grok AI (on-demand analysis)
export async function analyzeEmailGroq(email_text: string, subject?: string, sender?: string, urls?: string[]) {
  const endpoint = `${API_BASE_URL}/analyze-email-groq`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email_text, subject, sender, urls })
  });
  if (!res.ok) throw new Error('Failed to analyze email with Grok');
  return res.json();
}

// Get OAuth authentication status
export async function checkAuth(token?: string) {
  const endpoint = `${API_BASE_URL}/check-auth`;
  const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
  const res = await fetch(endpoint, {
    method: 'GET',
    headers
  });
  return res.ok;
}

// Login endpoint
export async function login() {
  const endpoint = `${API_BASE_URL}/login`;
  window.location.href = endpoint;
}

// Logout endpoint
export async function logout() {
  const endpoint = `${API_BASE_URL}/logout`;
  localStorage.removeItem('auth_token');
  localStorage.removeItem('gmail_access_token');
  window.location.href = endpoint;
}

// Chat with Groq LLM
interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp?: string;
}

interface ChatRequest {
  query: string;
  conversationHistory?: ChatMessage[];
  context?: Record<string, any>;
}

interface ChatResponse {
  message: string;
  conversationHistory?: ChatMessage[];
}

export async function chatWithGroq(request: ChatRequest): Promise<ChatResponse> {
  const endpoint = `${API_BASE_URL}/api/chat-groq`;
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  });
  if (!res.ok) {
    const error = await res.json();
    throw new Error(error.detail || 'Failed to chat with Groq');
  }
  return res.json();
}


