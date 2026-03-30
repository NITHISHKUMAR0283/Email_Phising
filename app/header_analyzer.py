"""
Email Header Analysis Module - Authentication & Spoofing Detection

Analyzes email headers for:
- SPF, DKIM, DMARC authentication results
- Routing history and hop count
- Display name spoofing
- Email sender address mismatches
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from email.parser import Parser
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Known legitimate company domains (for spoofing detection)
KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
}


def extract_authentication_results(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Extract SPF, DKIM, and DMARC authentication results from email headers.
    
    Args:
        headers: Dictionary of email headers
        
    Returns:
        Dict with 'spf', 'dkim', 'dmarc' keys containing status (pass/fail/softfail/none)
    """
    auth_results = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none"
    }
    
    # Get Authentication-Results header
    auth_header = headers.get("Authentication-Results", "")
    
    if not auth_header:
        return auth_results
    
    # SPF check
    spf_match = re.search(r'spf=(\S+)', auth_header, re.IGNORECASE)
    if spf_match:
        auth_results["spf"] = spf_match.group(1).lower()
    
    # DKIM check
    dkim_match = re.search(r'dkim=(\S+)', auth_header, re.IGNORECASE)
    if dkim_match:
        auth_results["dkim"] = dkim_match.group(1).lower()
    
    # DMARC check
    dmarc_match = re.search(r'dmarc=(\S+)', auth_header, re.IGNORECASE)
    if dmarc_match:
        auth_results["dmarc"] = dmarc_match.group(1).lower()
    
    return auth_results


def parse_received_headers(headers: Dict[str, str]) -> Tuple[int, Optional[str]]:
    """
    Parse Received headers to count routing hops and extract originating IP.
    
    Args:
        headers: Dictionary of email headers
        
    Returns:
        Tuple of (hop_count, originating_ip)
    """
    received_header = headers.get("Received", "")
    
    if not received_header:
        return 0, None
    
    # Count hops - Received header appears once per hop
    hop_count = len(received_header.split("\n")) if isinstance(received_header, str) else 1
    
    # Extract originating IP from first Received header (last one in chain)
    originating_ip = None
    ip_match = re.search(r'from \[(\d+\.\d+\.\d+\.\d+)\]', received_header)
    if ip_match:
        originating_ip = ip_match.group(1)
    else:
        # Try alternative format
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received_header)
        if ip_match:
            originating_ip = ip_match.group(1)
    
    return hop_count, originating_ip


def detect_display_name_spoofing(from_address: str, return_path: str) -> Tuple[bool, str]:
    """
    Detect if the display name matches a known brand but domain doesn't.
    
    Args:
        from_address: From header value (e.g., "Bank of America <noreply@phishing.com>")
        return_path: Return-Path header value
        
    Returns:
        Tuple of (is_spoofed, reason)
    """
    if not from_address or not return_path:
        return False, ""
    
    # Extract display name
    display_name_match = re.search(r'^"?([^<"]+)"?\s*<', from_address)
    display_name = display_name_match.group(1).strip().lower() if display_name_match else ""
    
    # Extract domain from From address
    from_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_address)
    from_domain = from_domain_match.group(1).lower() if from_domain_match else ""
    
    # Extract domain from Return-Path
    return_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', return_path)
    return_domain = return_domain_match.group(1).lower() if return_domain_match else ""
    
    # Check for spoofing
    for brand_name, legitimate_domains in KNOWN_BRANDS.items():
        # Check if display name contains brand
        if brand_name.lower() in display_name:
            # Check if From domain is NOT legitimate
            if from_domain and from_domain not in [d.lower() for d in legitimate_domains]:
                reason = f"Display name '{display_name}' spoofs '{brand_name}' but domain is '{from_domain}'"
                return True, reason
    
    return False, ""


def detect_mismatched_from(headers: Dict[str, str]) -> Tuple[bool, str]:
    """
    Detect if From header differs from Envelope From (Return-Path).
    This is a classic phishing indicator.
    
    Args:
        headers: Dictionary of email headers
        
    Returns:
        Tuple of (is_mismatched, reason)
    """
    from_header = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    
    if not from_header or not return_path:
        return False, ""
    
    # Extract domains
    from_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', from_header)
    return_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', return_path)
    
    from_domain = from_domain_match.group(1).lower() if from_domain_match else ""
    return_domain = return_domain_match.group(1).lower() if return_domain_match else ""
    
    # Compare domains
    if from_domain and return_domain and from_domain != return_domain:
        reason = f"From domain '{from_domain}' differs from Return-Path domain '{return_domain}'"
        return True, reason
    
    return False, ""


def check_suspicious_routing(hop_count: int, originating_ip: Optional[str]) -> Tuple[bool, str]:
    """
    Check for suspicious email routing patterns.
    
    Args:
        hop_count: Number of routing hops
        originating_ip: Original sender IP address
        
    Returns:
        Tuple of (is_suspicious, reason)
    """
    reasons = []
    
    # Excessive hops might indicate forwarding through proxy/relay
    if hop_count > 10:
        reasons.append(f"Excessive routing hops ({hop_count}) - possible relay/forwarding")
    
    # Very few hops without authentication is suspicious
    if hop_count < 2 and not originating_ip:
        reasons.append("Direct delivery without routing history - no originating IP")
    
    # Private IP addresses in routing are suspicious
    if originating_ip:
        private_patterns = [
            r'^10\.',           # 10.0.0.0/8
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # 172.16.0.0/12
            r'^192\.168\.',     # 192.168.0.0/16
            r'^127\.',          # Loopback
            r'^169\.254\.',     # Link-local
        ]
        if any(re.match(pattern, originating_ip) for pattern in private_patterns):
            reasons.append(f"Private IP address in routing: {originating_ip}")
    
    return len(reasons) > 0, " | ".join(reasons)


def calculate_header_risk_score(auth_results: Dict[str, str], is_spoofed: bool, 
                               is_mismatched: bool, is_suspicious_routing: bool) -> float:
    """
    Calculate overall header risk score (0-1).
    
    Strategy:
    - No authentication info (all "none") = 0.0 (legitimate emails often lack full headers)
    - Failed authentication when present = HIGH risk (0.3-0.8)
    - Spoofing/mismatch/suspicious routing = add points on top
    
    Args:
        auth_results: Dictionary of SPF/DKIM/DMARC results
        is_spoofed: Display name spoofing detected
        is_mismatched: Email address mismatch detected
        is_suspicious_routing: Suspicious routing pattern detected
        
    Returns:
        Risk score between 0 and 1
    """
    risk_score = 0.0
    
    # Count authentication results
    auth_present = sum(1 for v in auth_results.values() if v != "none")
    auth_failures = sum(1 for v in auth_results.values() if v in ["fail", "softfail"])
    
    # If some auth info is present:
    if auth_present > 0:
        # Each failure is worth 0.25 points (more aggressive)
        # Max 0.75 from auth failures alone
        risk_score += auth_failures * 0.25
        
        # Softfail from SPF is less critical than DKIM/DMARC fail
        if auth_results.get("spf") == "softfail":
            risk_score = max(0, risk_score - 0.05)  # Reduce slightly for softfail
    else:
        # No authentication info at all (common in legitimate emails)
        # Only penalize if there's spoofing/mismatch
        risk_score = 0.0
    
    # Spoofing indicators (0.15 points each - significant red flag)
    if is_spoofed:
        risk_score += 0.15
    if is_mismatched:
        risk_score += 0.15
    
    # Suspicious routing (0.10 points)
    if is_suspicious_routing:
        risk_score += 0.10
    
    # Cap at 1.0
    return min(risk_score, 1.0)


def analyze_email_headers(email_headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Main function: Analyze email headers for authentication and spoofing.
    
    Args:
        email_headers: Dictionary of email headers from message
        
    Returns:
        Dictionary with authentication results and security flags:
        {
            'spf': 'pass/fail/softfail/none',
            'dkim': 'pass/fail/softfail/none',
            'dmarc': 'pass/fail/softfail/none',
            'hops': int,
            'originating_ip': str or None,
            'is_spoofed': bool,
            'spoofing_reason': str,
            'is_mismatched': bool,
            'mismatch_reason': str,
            'is_suspicious_routing': bool,
            'routing_reason': str,
            'header_risk_score': float,
            'security_flags': list of suspicious indicators
        }
    """
    try:
        # 1. Extract authentication results
        auth_results = extract_authentication_results(email_headers)
        
        # 2. Parse routing information
        hop_count, originating_ip = parse_received_headers(email_headers)
        
        # 3. Detect display name spoofing
        from_addr = email_headers.get("From", "")
        return_path = email_headers.get("Return-Path", "")
        is_spoofed, spoofing_reason = detect_display_name_spoofing(from_addr, return_path)
        
        # 4. Detect address mismatch
        is_mismatched, mismatch_reason = detect_mismatched_from(email_headers)
        
        # 5. Check routing patterns
        is_suspicious_routing, routing_reason = check_suspicious_routing(hop_count, originating_ip)
        
        # 6. Calculate header risk score
        header_risk_score = calculate_header_risk_score(
            auth_results, is_spoofed, is_mismatched, is_suspicious_routing
        )
        
        # 7. Build security flags list
        security_flags = []
        if auth_results["spf"] in ["fail", "softfail"]:
            security_flags.append("SPF authentication failed")
        if auth_results["dkim"] in ["fail", "softfail"]:
            security_flags.append("DKIM signature invalid")
        if auth_results["dmarc"] in ["fail", "softfail"]:
            security_flags.append("DMARC policy violation")
        if is_spoofed:
            security_flags.append(f"Display name spoofing: {spoofing_reason}")
        if is_mismatched:
            security_flags.append(f"Address mismatch: {mismatch_reason}")
        if is_suspicious_routing:
            security_flags.append(f"Suspicious routing: {routing_reason}")
        
        return {
            "spf": auth_results["spf"],
            "dkim": auth_results["dkim"],
            "dmarc": auth_results["dmarc"],
            "hops": hop_count,
            "originating_ip": originating_ip,
            "is_spoofed": is_spoofed,
            "spoofing_reason": spoofing_reason,
            "is_mismatched": is_mismatched,
            "mismatch_reason": mismatch_reason,
            "is_suspicious_routing": is_suspicious_routing,
            "routing_reason": routing_reason,
            "header_risk_score": round(header_risk_score, 2),
            "security_flags": security_flags
        }
    
    except Exception as e:
        logger.error(f"Error analyzing email headers: {str(e)}")
        return {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
            "hops": 0,
            "originating_ip": None,
            "is_spoofed": False,
            "spoofing_reason": "",
            "is_mismatched": False,
            "mismatch_reason": "",
            "is_suspicious_routing": False,
            "routing_reason": "",
            "header_risk_score": 0.0,  # Default to no risk on parse error (missing headers is normal)
            "security_flags": []  # No flags if we can't parse
        }
