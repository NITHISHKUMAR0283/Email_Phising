"""
Heuristics for URL, domain, and header analysis
"""
from typing import List, Dict, Optional
import tldextract

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "reset your password", "account locked", "unusual sign-in", "secure your account", "temporary suspension", "click here", "action required", "confirm your identity"
]

SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".cn", ".tk"]


def analyze_heuristics(email_text: str, sender: Optional[str], urls: Optional[List[str]], headers: Optional[Dict[str, str]]) -> Dict:
    signals = []
    # Keyword check
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in email_text.lower():
            signals.append(f"Suspicious phrase: {kw}")
    # URL/domain check
    if urls:
        for url in urls:
            ext = tldextract.extract(url)
            tld = f".{ext.suffix}" if ext.suffix else ""
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
