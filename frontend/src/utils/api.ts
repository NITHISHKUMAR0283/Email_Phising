
// Analyze email (expects object with email_text, subject, sender, urls, headers)
export async function analyzeEmail(email: any) {
  const res = await fetch('http://localhost:8000/analyze-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(email),
  });
  if (!res.ok) throw new Error('Failed to analyze email');
  return res.json();
}

// Fetch logs for log table
export async function fetchLogs() {
  const res = await fetch('http://localhost:8000/logs');
  if (!res.ok) throw new Error('Failed to fetch logs');
  return res.json();
}
