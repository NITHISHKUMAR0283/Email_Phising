"""
Grok AI integration for generating human-readable phishing explanations.
Uses Groq API to analyze emails and explain why they are phishing.
Falls back to heuristics-based analysis if Grok fails.
"""

import re
from typing import Dict, Any, Optional
import requests
from datetime import datetime
import time
import threading

# Groq API configuration (not xAI)
GROK_API_KEY = "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"
GROK_API_URL = "https://api.groq.com/openai/v1/chat/completions"  # Correct Groq endpoint
GROK_ENABLED = True  # Enable Groq with correct configuration

# Rate limiting & request serialization
LAST_REQUEST_TIME = 0
MIN_REQUEST_INTERVAL = 0  # No rate limit - send requests immediately

def generate_grok_analysis(
    email_text: str,
    subject: str,
    sender: str,
    urls: list,
    heuristics: Dict[str, Any],
    risk_score: float
) -> Dict[str, Any]:
    """
    Generate AI-powered explanation using Grok about why email is phishing/safe.
    Falls back to heuristics-based analysis if Grok fails.
    
    Args:
        email_text: Full email body
        subject: Email subject
        sender: Sender email address
        urls: List of suspicious URLs
        heuristics: Heuristic analysis signals
        risk_score: Risk score (0-1)
    
    Returns:
        Dict with 'explanation', 'red_flags', 'ai_summary', 'suspicious_phrases'
    """
    
    # If Grok is disabled, use heuristics-based fallback
    if not GROK_ENABLED:
        print("[INFO] Grok disabled - using heuristics-based analysis")
        return generate_heuristics_fallback(email_text, subject, sender, urls, heuristics, risk_score)
    
    try:
        # Prepare analysis summary from heuristics
        heuristic_summary = format_heuristics_summary(heuristics)
        
        # Create the prompt for Grok
        if risk_score > 0.7:  # Only strong phishing indicators (70%+)
            prompt = create_phishing_analysis_prompt(
                email_text, subject, sender, urls, heuristic_summary, risk_score
            )
        else:  # 70% and below = likely legitimate, BUT still analyze for context
            prompt = create_safety_analysis_prompt(
                email_text, subject, sender, urls, heuristic_summary, risk_score
            )
        
        # Call Grok API
        response = call_grok_api(prompt)
        
        if response:
            # Parse the response
            analysis = parse_grok_response(response, risk_score > 0.7, email_text)
            return analysis
        else:
            print("[WARNING] Grok API returned empty response - falling back to heuristics")
            return generate_heuristics_fallback(email_text, subject, sender, urls, heuristics, risk_score)
            
    except Exception as e:
        print(f"[ERROR] Grok analysis failed: {str(e)} - falling back to heuristics")
        return generate_heuristics_fallback(email_text, subject, sender, urls, heuristics, risk_score)


def generate_grok_batch_analysis(emails_data: list) -> list:
    """
    Analyze multiple emails (up to 3) in a SINGLE Groq API call to reduce rate limiting.
    
    Args:
        emails_data: List of dicts with keys:
            - email_text, subject, sender, urls, heuristics, risk_score, msg_id
    
    Returns:
        List of analysis dicts (one per email) with same structure as generate_grok_analysis()
    """
    
    if not GROK_ENABLED or not emails_data:
        print("[INFO] Batch Grok disabled or no emails - using heuristics-based analysis")
        return [generate_heuristics_fallback(
            e.get("email_text", ""),
            e.get("subject", ""),
            e.get("sender", ""),
            e.get("urls", []),
            e.get("heuristics", {}),
            e.get("risk_score", 0.5)
        ) for e in emails_data]
    
    try:
        # Create batch prompt for multiple emails
        prompt = create_batch_analysis_prompt(emails_data)
        
        # Call Grok API once for all emails
        response = call_grok_api(prompt)
        
        if response:
            # Parse batch response
            analyses = parse_grok_batch_response(response, emails_data)
            return analyses
        else:
            print("[WARNING] Grok batch API returned empty response - falling back to heuristics")
            return [generate_heuristics_fallback(
                e.get("email_text", ""),
                e.get("subject", ""),
                e.get("sender", ""),
                e.get("urls", []),
                e.get("heuristics", {}),
                e.get("risk_score", 0.5)
            ) for e in emails_data]
            
    except Exception as e:
        print(f"[ERROR] Grok batch analysis failed: {str(e)} - falling back to heuristics")
        return [generate_heuristics_fallback(
            e.get("email_text", ""),
            e.get("subject", ""),
            e.get("sender", ""),
            e.get("urls", []),
            e.get("heuristics", {}),
            e.get("risk_score", 0.5)
        ) for e in emails_data]


def create_batch_analysis_prompt(emails_data: list) -> str:
    """Create prompt for Grok to analyze multiple emails at once."""
    
    emails_str = ""
    for idx, email in enumerate(emails_data, 1):
        text_preview = email.get("email_text", "")[:300] if email.get("email_text") else "No body"
        urls_str = ", ".join(email.get("urls", [])[:2]) if email.get("urls") else "None"
        risk = email.get("risk_score", 0.5)
        
        emails_str += f"""
EMAIL {idx}:
Subject: {email.get("subject", "")[:80]}
From: {email.get("sender", "")[:50]}
URLs: {urls_str}
Risk Score: {risk*100:.0f}%
Body preview: {text_preview}
---"""
    
    prompt = f"""Analyze these {len(emails_data)} emails for phishing. Return ONLY valid JSON array (NO other text).
IMPORTANT: Do NOT flag whitespace, line breaks, or formatting issues as phishing. These are normal email formatting.
Focus on: malicious intent, credential theft, fake domains, urgent requests for sensitive data.

{emails_str}

Return ONLY a JSON array (NO markdown, NO explanation, just raw JSON):
[
  {{
    "email_index": 1,
    "risk_score": 0.5,
    "explanation": "Why this is phishing/safe (2-3 sentences)",
    "is_valid_domain": true,
    "domain": "extracted domain",
    "highlighted_text": ["malicious phrase1"],
    "red_flags": ["actual threat"],
    "recommendation": "Delete/Safe to read"
  }},
  {{
    "email_index": 2,
    "risk_score": 0.3,
    "explanation": "Analysis for email 2",
    "is_valid_domain": true,
    "domain": "domain2",
    "highlighted_text": [],
    "red_flags": [],
    "recommendation": "Safe to read"
  }}
]"""
    
    return prompt


def create_phishing_analysis_prompt(
    email_text: str, subject: str, sender: str, urls: list, heuristics: str, risk_score: float
) -> str:
    """Create prompt for Grok to analyze likely phishing email."""
    
    text_preview = email_text[:500] if email_text else "No body"
    urls_str = ", ".join(urls[:3]) if urls else "None"
    
    prompt = f"""Analyze if this email is phishing. Extract domain from sender/URLs. Return JSON only.
IMPORTANT VALIDATION RULES:
- URLs starting with "https://" ARE encrypted - do NOT flag as lacking HTTPS
- Only flag URLs starting with "http://" (without S) as unencrypted
- Do NOT flag whitespace, line breaks, or formatting issues as phishing
- Focus on: malicious intent, credential theft, fake domains, urgent requests for sensitive data, spoofed companies

Subject: {subject[:100]}
From: {sender[:50]}
URLs: {urls_str}
Heuristic Risk: {risk_score*100:.0f}%

Body preview: {text_preview[:300]}

Return ONLY valid JSON (NO other text):
{{
  "risk_score": 0.85,
  "explanation": "Why this is phishing (2-3 sentences)",
  "is_valid_domain": false,
  "domain": "extracted domain or sender domain",
  "highlighted_text": ["genuine malicious phrase1", "malicious phrase2"],
  "red_flags": ["actual threat flag1", "actual threat flag2"],
  "recommendation": "Delete/Report"
}}"""

    return prompt


def create_safety_analysis_prompt(
    email_text: str, subject: str, sender: str, urls: list, heuristics: str, risk_score: float
) -> str:
    """Create prompt for Grok to analyze likely legitimate email."""
    
    text_preview = email_text[:500] if email_text else "No body"
    urls_str = ", ".join(urls[:3]) if urls else "None"
    
    prompt = f"""Analyze if this email is legitimate. Validate domain. Return JSON only.
IMPORTANT VALIDATION RULES:
- URLs starting with "https://" ARE encrypted and secure - do NOT flag as lacking HTTPS
- Only flag URLs starting with "http://" (without S) as potentially unencrypted
- Do NOT flag whitespace, line breaks, or formatting issues as problems
- Only flag if there are actual security concerns: mismatched domains, urgent requests, or credential theft attempts

Subject: {subject[:100]}
From: {sender[:50]}
URLs: {urls_str}
Heuristic Risk: {risk_score*100:.0f}%

Body preview: {text_preview[:300]}

Return ONLY valid JSON (NO other text):
{{
  "risk_score": 0.15,
  "explanation": "Why this is legitimate (2-3 sentences)",
  "is_valid_domain": true,
  "domain": "extracted domain or sender domain",
  "highlighted_text": [],
  "red_flags": ["only real security concerns"],
  "recommendation": "Safe to read"
}}"""

    return prompt


def call_grok_api(prompt: str, max_retries: int = 3) -> Optional[str]:
    """
    Call Groq API without serialization - concurrent requests allowed.
    """
    global LAST_REQUEST_TIME
    
    # Rate limiting: wait if necessary
    elapsed = time.time() - LAST_REQUEST_TIME
    if elapsed < MIN_REQUEST_INTERVAL:
        wait = MIN_REQUEST_INTERVAL - elapsed
        print(f"[DEBUG] Rate limiting: waiting {wait:.1f}s...")
        time.sleep(wait)
    
    for attempt in range(max_retries):
        try:
            headers = {
                "Authorization": f"Bearer {GROK_API_KEY}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Respond ONLY with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "model": "llama-3.1-8b-instant",  # Faster model with higher rate limits
                "temperature": 0.5,
                "max_tokens": 512
            }
            
            print(f"[DEBUG] Groq API Call (Attempt {attempt+1}/{max_retries})")
            
            LAST_REQUEST_TIME = time.time()
            response = requests.post(GROK_API_URL, json=payload, headers=headers, timeout=30)
            
            print(f"[DEBUG] Groq Status: {response.status_code}")
            
            # Handle rate limiting
            if response.status_code == 429:  # Too Many Requests
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                print(f"[DEBUG] Rate limited. Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                continue
            
            if response.status_code != 200:
                error_detail = response.text[:300] if response.text else "No detail"
                print(f"[DEBUG] Error: {error_detail}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    continue
                return None
            
            # Success
            data = response.json()
            if data.get("choices") and len(data["choices"]) > 0:
                result = data["choices"][0]["message"]["content"]
                print(f"[DEBUG] ✅ Groq success")
                return result
            
            return None
            
        except requests.exceptions.Timeout:
            print(f"[DEBUG] Timeout on attempt {attempt+1}")
            if attempt < max_retries - 1:
                time.sleep(2)
                continue
            return None
        except Exception as e:
            print(f"[DEBUG] Exception: {str(e)[:100]}")
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            return None
    
    return None


def parse_grok_response(response: str, is_phishing: bool, email_text: str = "") -> Dict[str, Any]:
    """Parse Grok API response and extract risk score + domain + analysis."""
    try:
        # Extract JSON from response
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            import json
            data = json.loads(json_match.group())
            
            # Extract risk score (0-1) - PRIMARY SCORE FROM GROQ
            risk_score = data.get("risk_score", 0.5)
            if not isinstance(risk_score, (int, float)):
                risk_score = 0.5
            risk_score = min(max(float(risk_score), 0.0), 1.0)  # Ensure 0-1 range
            
            # Extract domain validation info
            domain = data.get("domain", "Unknown")
            is_valid_domain = data.get("is_valid_domain", False)
            
            # Extract highlighted text (suspicious phrases)
            highlighted_text = data.get("highlighted_text", [])
            
            # Validate phrases exist in email
            if email_text and highlighted_text:
                validated_phrases = []
                for phrase in highlighted_text:
                    if phrase.lower() in email_text.lower():
                        validated_phrases.append(phrase)
                highlighted_text = validated_phrases if validated_phrases else highlighted_text
            
            return {
                "risk_score": risk_score,  # PRIMARY AI-GENERATED SCORE (0-1)
                "explanation": data.get("explanation", response),
                "domain": domain,
                "is_valid_domain": is_valid_domain,
                "highlighted_text": highlighted_text,
                "red_flags": data.get("red_flags", []),
                "recommendation": data.get("recommendation", "Review carefully"),
                "suspicious_phrases": highlighted_text  # For compatibility
            }
    except Exception as e:
        print(f"Error parsing Grok response: {str(e)}")
    
    # Fallback: use default risk score
    return {
        "risk_score": 0.5,
        "explanation": response,
        "domain": "Unknown",
        "is_valid_domain": False,
        "highlighted_text": [],
        "red_flags": [],
        "recommendation": "Review carefully",
        "suspicious_phrases": []
    }


def parse_grok_batch_response(response: str, emails_data: list) -> list:
    """Parse Grok batch API response and extract analysis for each email."""
    try:
        import json
        # Extract JSON array from response
        json_match = re.search(r'\[.*\]', response, re.DOTALL)
        if json_match:
            analyses_list = json.loads(json_match.group())
            
            results = []
            for email_data in emails_data:
                email_text = email_data.get("email_text", "")
                
                # Find matching analysis by email_index (1-based)
                analysis_data = None
                for item in analyses_list:
                    if isinstance(item, dict) and item.get("email_index") is not None:
                        # Match by index
                        analysis_data = item
                        break
                
                if not analysis_data:
                    # Fallback if analysis not found
                    results.append({
                        "risk_score": 0.5,
                        "explanation": "Could not parse analysis",
                        "domain": "Unknown",
                        "is_valid_domain": False,
                        "highlighted_text": [],
                        "red_flags": [],
                        "recommendation": "Review carefully",
                        "suspicious_phrases": []
                    })
                    continue
                
                # Extract risk score (0-1)
                risk_score = analysis_data.get("risk_score", 0.5)
                if not isinstance(risk_score, (int, float)):
                    risk_score = 0.5
                risk_score = min(max(float(risk_score), 0.0), 1.0)  # Ensure 0-1 range
                
                # Extract domain validation info
                domain = analysis_data.get("domain", "Unknown")
                is_valid_domain = analysis_data.get("is_valid_domain", False)
                
                # Extract highlighted text (suspicious phrases)
                highlighted_text = analysis_data.get("highlighted_text", [])
                
                # Validate phrases exist in email
                if email_text and highlighted_text:
                    validated_phrases = []
                    for phrase in highlighted_text:
                        if phrase.lower() in email_text.lower():
                            validated_phrases.append(phrase)
                    highlighted_text = validated_phrases if validated_phrases else highlighted_text
                
                results.append({
                    "risk_score": risk_score,
                    "explanation": analysis_data.get("explanation", "Analysis provided by Groq"),
                    "domain": domain,
                    "is_valid_domain": is_valid_domain,
                    "highlighted_text": highlighted_text,
                    "red_flags": analysis_data.get("red_flags", []),
                    "recommendation": analysis_data.get("recommendation", "Review carefully"),
                    "suspicious_phrases": highlighted_text  # For compatibility
                })
            
            return results
    except Exception as e:
        print(f"Error parsing Grok batch response: {str(e)}")
    
    # Fallback: return heuristics-based analysis for all
    return [generate_heuristics_fallback(
        email.get("email_text", ""),
        email.get("subject", ""),
        email.get("sender", ""),
        email.get("urls", []),
        email.get("heuristics", {}),
        email.get("risk_score", 0.5)
    ) for email in emails_data]


def format_heuristics_summary(heuristics: Dict[str, Any]) -> str:
    """Format heuristics data for Grok prompt."""
    summary = "Detected signals:\n"
    
    if isinstance(heuristics, dict):
        for key, value in heuristics.items():
            if isinstance(value, dict):
                summary += f"- {key}: {value.get('reason', str(value))}\n"
            elif isinstance(value, list):
                summary += f"- {key}: {', '.join(str(v) for v in value)}\n"
            else:
                summary += f"- {key}: {value}\n"
    
    return summary if summary != "Detected signals:\n" else "No additional signals detected"


def generate_heuristics_fallback(
    email_text: str,
    subject: str,
    sender: str,
    urls: list,
    heuristics: Dict[str, Any],
    risk_score: float
) -> Dict[str, Any]:
    """
    Fallback analysis using heuristics when Grok API fails.
    Extracts suspicious phrases from both heuristics and direct text analysis.
    """
    
    # Extract common phishing phrases/keywords from email text
    phishing_indicators = [
        "verify", "confirm", "urgent", "act now", "immediate action", "click here",
        "update account", "verify account", "confirm identity", "validate", "confirm account",
        "unusual activity", "security alert", "verify information", "click immediately",
        "don't ignore", "do not ignore", "authenticate", "reactivate",
        "suspended", "limited", "restricted", "confirm credentials", "update payment",
        "billing problem", "account suspended", "account limited", "re-enter",
        "enrol", "enroll", "register now", "sign up", "unlock", "claim",
        "won", "congratulations", "reward", "prize", "exclusive offer",
    ]
    
    # Find matching phrases in email text
    suspicious_phrases = []
    email_lower = email_text.lower()
    for phrase in phishing_indicators:
        if phrase in email_lower and phrase not in suspicious_phrases:
            # Find the actual phrase in original text for proper casing
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            matches = pattern.finditer(email_text)
            for match in matches:
                actual_phrase = match.group()
                if actual_phrase not in suspicious_phrases:
                    suspicious_phrases.append(actual_phrase)
                    if len(suspicious_phrases) >= 5:  # Limit to top 5
                        break
        if len(suspicious_phrases) >= 5:
            break
    
    # Extract URLs as red flags
    url_red_flags = [f"Suspicious URL detected: {url}" for url in urls[:3]]
    
    # Generate explanation based on risk score
    if risk_score > 0.6:
        explanation = f"This email has a {risk_score*100:.0f}% phishing risk score. It contains multiple suspicious indicators including phishing keywords and potentially malicious URLs."
        red_flags = [
            "Contains urgency/action language typical of phishing",
            "Email requests sensitive information",
            "Sender domain may not match claimed organization"
        ] + url_red_flags[:1]
        ai_summary = "Do NOT click links or provide personal information. Report to IT security."
    else:
        explanation = f"This email appears legitimate with only a {risk_score*100:.0f}% risk score. No significant phishing indicators detected."
        red_flags = [
            "Email comes from known legitimate organization",
            "No urgent/deceptive language detected",
            "URLs appear legitimate"
        ]
        ai_summary = "Safe to interact with this email."
    
    return {
        "explanation": explanation,
        "red_flags": red_flags,
        "ai_summary": ai_summary,
        "suspicious_phrases": suspicious_phrases
    }
