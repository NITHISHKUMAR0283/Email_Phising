"""
VirusTotal API Integration for URL/Domain Reputation Analysis
Detects known phishing URLs and malware domains
"""

import requests
import os
from typing import Dict, Any, Optional, List, Tuple
import time
from urllib.parse import urlparse

# Get API key from environment variable (SECURE!)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_URL = "https://www.virustotal.com/api/v3"

# Rate limiting: 4 requests/minute on free tier
VT_REQUEST_INTERVAL = 15  # seconds between requests
LAST_VT_REQUEST = 0


def rate_limit_vt():
    """Rate limit VT API calls to stay within free tier limits."""
    global LAST_VT_REQUEST
    
    if VT_API_KEY and LAST_VT_REQUEST > 0:
        elapsed = time.time() - LAST_VT_REQUEST
        if elapsed < VT_REQUEST_INTERVAL:
            time.sleep(VT_REQUEST_INTERVAL - elapsed)
    
    LAST_VT_REQUEST = time.time()


def is_vt_available() -> bool:
    """Check if VirusTotal API is configured."""
    return bool(VT_API_KEY)


def check_url_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Scan URL against VirusTotal for known phishing/malware.
    
    Args:
        url: Full URL to check
        
    Returns:
        Dict with reputation data or None if unavailable
        {
            "malicious": int (number of vendors flagging),
            "suspicious": int,
            "undetected": int,
            "harmless": int,
            "reputation": int (-100 to +100),
            "is_phishing": bool,
            "last_scanned": str (timestamp)
        }
    """
    if not VT_API_KEY:
        return None
    
    try:
        rate_limit_vt()
        
        headers = {"x-apikey": VT_API_KEY}
        
        # Encode URL for safe transmission
        url_encoded = url.replace("=", "%3D").replace("&", "%26")
        
        # Query endpoint (checks against cached results, no new scan)
        response = requests.get(
            f"{VT_URL}/urls",
            params={"query": url},
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get("data"):
                result = data["data"][0]["attributes"]
                stats = result.get("last_analysis_stats", {})
                categories = result.get("categories", {})
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": result.get("reputation", 0),
                    "is_phishing": categories.get("phishing", False),
                    "is_malware": categories.get("malware", False),
                    "last_scanned": result.get("last_submission_date", "Unknown")
                }
        
        return None
    
    except Exception as e:
        print(f"[VT Error] URL check failed: {str(e)[:100]}")
        return None


def check_domain_virustotal(domain: str) -> Optional[Dict[str, Any]]:
    """
    Check domain reputation on VirusTotal.
    
    Args:
        domain: Domain name to check (e.g., "evil.com")
        
    Returns:
        Dict with domain reputation or None
        {
            "reputation": int,
            "categories": dict,
            "is_malicious": bool,
            "last_dns_records": dict
        }
    """
    if not VT_API_KEY:
        return None
    
    try:
        rate_limit_vt()
        
        headers = {"x-apikey": VT_API_KEY}
        
        # Get domain info
        response = requests.get(
            f"{VT_URL}/domains/{domain}",
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            
            return {
                "reputation": data.get("reputation", 0),
                "categories": data.get("categories", {}),
                "is_malicious": data.get("reputation", 0) < -50,
                "last_dns_records": data.get("last_dns_records", {})
            }
        
        return None
    
    except Exception as e:
        print(f"[VT Error] Domain check failed: {str(e)[:100]}")
        return None


def analyze_urls_virustotal(urls: List[str]) -> Tuple[float, List[str]]:
    """
    Analyze multiple URLs against VirusTotal.
    
    Args:
        urls: List of URLs to check
        
    Returns:
        (vt_score: 0-1, findings: list of threat descriptions)
    """
    if not urls or not VT_API_KEY:
        return 0.0, []
    
    vt_score = 0.0
    findings = []
    high_risk_urls = []
    
    # Check first 3 URLs (respect rate limit)
    for url in urls[:3]:
        try:
            vt_data = check_url_virustotal(url)
            
            if vt_data:
                malicious_count = vt_data.get("malicious", 0)
                reputation = vt_data.get("reputation", 0)
                is_phishing = vt_data.get("is_phishing", False)
                
                # Scoring logic
                if malicious_count >= 20:
                    # 20+ engines flagged = VERY HIGH CONFIDENCE
                    vt_score = 0.95
                    findings.append(f"URL flagged by {malicious_count} antivirus engines as malicious")
                    high_risk_urls.append(url)
                
                elif malicious_count >= 10:
                    # 10-20 engines = HIGH confidence
                    vt_score = max(vt_score, 0.85)
                    findings.append(f"URL flagged by {malicious_count} AV engines")
                    high_risk_urls.append(url)
                
                elif is_phishing:
                    # Explicitly phishing = HIGH
                    vt_score = max(vt_score, 0.80)
                    findings.append("URL flagged as phishing by multiple AV engines")
                    high_risk_urls.append(url)
                
                elif malicious_count >= 5:
                    # 5-10 engines = MEDIUM
                    vt_score = max(vt_score, 0.70)
                    findings.append(f"URL flagged by {malicious_count} AV engines")
                
                elif reputation < -50:
                    # Bad reputation = MEDIUM
                    vt_score = max(vt_score, 0.60)
                    findings.append("URL has malicious reputation score")
                
                elif reputation < 0:
                    # Slightly bad = LOW
                    vt_score = max(vt_score, 0.30)
                    findings.append("URL has slightly negative reputation")
        
        except Exception as e:
            print(f"[VT] Error analyzing {url}: {str(e)[:50]}")
    
    return vt_score, findings


def analyze_domain_virustotal(domain: str) -> Tuple[float, List[str]]:
    """
    Analyze domain reputation.
    
    Args:
        domain: Domain to check
        
    Returns:
        (vt_score: 0-1, findings: list)
    """
    if not domain or not VT_API_KEY:
        return 0.0, []
    
    try:
        # Extract domain from email/URL if needed
        if "@" in domain:
            domain = domain.split("@")[1].split(">")[0]
        
        vt_data = check_domain_virustotal(domain)
        
        if vt_data:
            reputation = vt_data.get("reputation", 0)
            is_malicious = vt_data.get("is_malicious", False)
            categories = vt_data.get("categories", {})
            
            findings = []
            score = 0.0
            
            if is_malicious:
                score = 0.80
                findings.append(f"Domain has malicious reputation ({reputation})")
            
            elif reputation < -50:
                score = 0.70
                findings.append("Domain flagged with negative reputation")
            
            elif reputation < 0:
                score = 0.30
                findings.append("Domain has slightly suspicious reputation")
            
            if categories.get("phishing"):
                score = max(score, 0.85)
                findings.append("Domain linked to phishing campaigns")
            
            return score, findings
        
        return 0.0, []
    
    except Exception as e:
        print(f"[VT] Error analyzing domain: {str(e)[:50]}")
        return 0.0, []


def get_vt_summary(urls: List[str]) -> Dict[str, Any]:
    """
    Get comprehensive VT analysis summary for reporting.
    
    Returns dict with all findings for display in UI.
    """
    if not urls or not VT_API_KEY:
        return {"status": "unavailable"}
    
    try:
        all_findings = []
        highest_score = 0.0
        
        for url in urls[:3]:
            vt_data = check_url_virustotal(url)
            
            if vt_data:
                all_findings.append({
                    "url": url,
                    "malicious": vt_data.get("malicious", 0),
                    "suspicious": vt_data.get("suspicious", 0),
                    "reputation": vt_data.get("reputation", 0),
                    "is_phishing": vt_data.get("is_phishing", False)
                })
                
                highest_score = max(highest_score, 
                    min(1.0, vt_data.get("malicious", 0) / 10))
        
        return {
            "status": "available",
            "findings": all_findings,
            "highest_risk": highest_score
        }
    
    except Exception as e:
        print(f"[VT] Summary error: {str(e)[:50]}")
        return {"status": "error"}
