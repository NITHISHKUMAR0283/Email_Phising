// API utility for PhishGuard AI frontend

// New API for /analyze-email endpoint
export async function analyzeEmail(email_text: string, sender?: string, urls?: string[], headers?: Record<string, string>) {
  const res = await fetch('https://email-phising.onrender.com/analyze-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email_text, sender, urls, headers })
  });
  return res.json();
}
