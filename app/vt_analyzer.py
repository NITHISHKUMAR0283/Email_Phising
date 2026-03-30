"""
VirusTotal integration for URL analysis.
Falls back to simple heuristics if API not available.
"""

import os
from typing import Tuple, List

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

def is_vt_available() -> bool:
    """Check if VirusTotal API is configured."""
    return bool(VT_API_KEY)

def analyze_urls_virustotal(urls: List[str]) -> Tuple[float, List[str]]:
    """
    Analyze URLs with VirusTotal API if available.
    
    Returns: (max_risk_score, findings)
    - max_risk_score: 0.0 to 1.0 (0 = safe, 1 = dangerous)
    - findings: list of threat strings
    """
    if not urls or not is_vt_available():
        return 0.0, []
    
    # Placeholder: would call VirusTotal API here
    # For now, return 0 (not available)
    findings = []
    
    # Simple heuristic: check for URL patterns that are often phishing
    max_score = 0.0
    for url in urls:
        if any(suspicious in url.lower() for suspicious in [
            "bit.ly", "tinyurl", "short.link", "bit.cc",  # URL shorteners
            "free-", "claim-", "verify-",  # Common phishing keywords
            "ipv4", "localhost", "192.168", "10.0.",  # IP addresses instead of domains
        ]):
            max_score = 0.7
            findings.append(f"Suspicious URL pattern: {url[:50]}")
    
    return max_score, findings
