"""
Dedicated URL analysis using Groq AI.
Asks Groq specifically about URL safety and validity.
"""

import re
import requests
from typing import Dict, List, Any, Optional
import time

# Groq API configuration
GROK_API_KEY = "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"
GROK_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def analyze_urls_with_grok(urls: List[str]) -> Dict[str, Any]:
    """
    Ask Grok specifically about URLs and get detailed verdict for each.
    Returns: {
        'overall_risk_score': 0-1,
        'urls_analysis': [
            {
                'url': 'https://...',
                'is_safe': True/False,
                'risk_score': 0-1,
                'verdict': 'Safe domain' / 'Phishing domain' / etc,
                'reasoning': 'Why...'
            }
        ]
    }
    """
    if not urls or len(urls) == 0:
        return {
            'overall_risk_score': 0.0,
            'urls_analysis': [],
            'status': 'no_urls'
        }
    
    # Create prompt asking Grok to analyze each URL
    urls_list = "\n".join([f"{i+1}. {url}" for i, url in enumerate(urls[:5])])  # Max 5 URLs
    
    prompt = f"""You are a cybersecurity expert. Analyze these URLs and determine if they are legitimate or phishing.
For each URL, evaluate:
1. Is the domain legitimately registered? (e.g., files-editor.com is likely real)
2. Does the URL scheme make sense? (https = encrypted and good, http = less secure)
3. Are there any red flags in the URL structure?
4. Is this a known phishing domain?

CRITICAL: If a URL starts with "https://", it IS encrypted and secure. Do NOT flag it as lacking encryption.

URLs to analyze:
{urls_list}

Return ONLY a valid JSON object (NO markdown, NO explanations):
{{
  "overall_risk_score": 0.2,
  "urls_analysis": [
    {{
      "url": "https://files-editor.com/app/...",
      "is_safe": true,
      "risk_score": 0.1,
      "verdict": "Legitimate encrypted connection",
      "reasoning": "HTTPS protocol provides encryption. Domain files-editor.com appears legitimate. No phishing indicators detected."
    }},
    {{
      "url": "https://files-editor.com/email-unsubscribe?token=...",
      "is_safe": true,
      "risk_score": 0.15,
      "verdict": "Safe domain with token authentication",
      "reasoning": "Same legitimate domain. Token-based authentication is normal. HTTPS encrypts all data."
    }}
  ]
}}"""
    
    try:
        headers = {
            "Authorization": f"Bearer {GROK_API_KEY}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity expert specializing in URL analysis and phishing detection. Respond ONLY with valid JSON, no other text."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "model": "llama-3.1-8b-instant",
            "temperature": 0.3,  # Lower temp for more factual/consistent output
            "max_tokens": 1024
        }
        
        print("[URL GROK] Asking Grok about URLs...")
        response = requests.post(GROK_API_URL, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("choices") and len(data["choices"]) > 0:
                result_text = data["choices"][0]["message"]["content"]
                print("[URL GROK] ✅ Got response from Grok")
                
                # Parse the JSON response
                json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
                if json_match:
                    import json
                    analysis = json.loads(json_match.group())
                    return analysis
        
        print(f"[URL GROK] ❌ Groq returned status {response.status_code}")
        
    except Exception as e:
        print(f"[URL GROK] ❌ Error calling Grok: {str(e)[:100]}")
    
    # Fallback: return neutral response
    return {
        'overall_risk_score': 0.5,
        'urls_analysis': [{'url': u, 'is_safe': True, 'risk_score': 0.3, 'verdict': 'Unable to analyze', 'reasoning': 'Grok analysis failed'} for u in urls],
        'status': 'fallback'
    }


def get_url_risk_score(urls: List[str]) -> float:
    """
    Get overall risk score based on Grok's URL analysis.
    Returns: 0-1 risk score
    """
    analysis = analyze_urls_with_grok(urls)
    return analysis.get('overall_risk_score', 0.5)
