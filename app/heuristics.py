
from typing import List, Dict, Optional
import tldextract

# List of suspicious keywords/phrases for phishing detection
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "reset your password", "account locked", "unusual sign-in", "secure your account", "temporary suspension", "click here", "action required", "confirm your identity",
    "mandatory", "compliance", "it policy", "training", "cybersecurity", "lockout", "survey", "deadline"
]

# Whitelist of known safe internal domains
INTERNAL_DOMAIN_WHITELIST = [
    "internal.company.com",
    "intranet.company.com",
    "portal.company.com",
    "internal-srm-ist.edu"
]

# List of suspicious TLDs
SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".cn", ".tk"]

def analyze_heuristics(email_text: str, sender: Optional[str], urls: Optional[List[str]], headers: Optional[Dict[str, str]]) -> Dict:
    """
    Analyze email using heuristics: keywords, URLs, headers, sender domain.
    Returns a dict with a list of triggered heuristic signals.
    """
    signals = []
    text_lower = email_text.lower()
    # Keyword check
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in text_lower:
            signals.append(f"Suspicious phrase: {kw}")
    # URL/domain check
    if urls:
        for url in urls:
            ext = tldextract.extract(url)
            tld = f".{ext.suffix}" if ext.suffix else ""
            domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else url
            # Internal-looking domain but not in whitelist
            if ("internal" in domain or "intranet" in domain or "portal" in domain) and domain not in INTERNAL_DOMAIN_WHITELIST:
                signals.append(f"Suspicious internal domain: {domain}")
            if tld in SUSPICIOUS_TLDS:
                signals.append(f"Suspicious TLD: {tld}")
            if any(kw in url.lower() for kw in ["login", "secure", "update", "verify"]):
                signals.append(f"Suspicious URL keyword in: {url}")
    # Header checks
    if headers:
        if headers.get("SPF", "").lower() == "fail":
            signals.append("SPF failed")
        if headers.get("DKIM", "").lower() == "fail":
            signals.append("DKIM failed")
        if headers.get("DMARC", "").lower() == "fail":
            signals.append("DMARC failed")
    # Sender domain check
    if sender:
        ext = tldextract.extract(sender)
        tld = f".{ext.suffix}" if ext.suffix else ""
        if tld in SUSPICIOUS_TLDS:
            signals.append(f"Sender TLD suspicious: {tld}")
    return {"signals": signals}
