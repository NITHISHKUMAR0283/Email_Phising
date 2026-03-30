"""
Whitelist management for trusted senders to reduce false positives.
"""

# Known trusted domains
WHITELISTED_DOMAINS = {
    "gmail.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "stackoverflow.com",
    "outlook.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "edu.sa",
    "kau.edu.sa",
    "axatp.com",
}

def is_domain_whitelisted(domain: str) -> bool:
    """Check if a domain is whitelisted (trusted sender)."""
    if not domain:
        return False
    domain = domain.lower()
    return domain in WHITELISTED_DOMAINS or domain.endswith(".edu")

def is_legitimate_urgency(subject: str) -> bool:
    """Check if urgency language is legitimate context."""
    # Legitimate urgency keywords that appear in real business emails
    legitimate_keywords = [
        "project deadline",
        "weekly report",
        "monthly review",
        "quarterly results",
        "annual summary",
    ]
    subject_lower = subject.lower()
    return any(keyword in subject_lower for keyword in legitimate_keywords)

def is_educational_content(body: str) -> bool:
    """Check if content is educational/informational."""
    educational_keywords = [
        "tutorial",
        "guide",
        "documentation",
        "best practices",
        "how to",
        "webinar",
        "training",
    ]
    body_lower = body.lower()
    return any(keyword in body_lower for keyword in educational_keywords)

def get_whitelist_info(domain: str) -> str:
    """Get info about why a domain is whitelisted."""
    if not domain:
        return "Unknown domain"
    domain = domain.lower()
    if domain in WHITELISTED_DOMAINS:
        return f"Known trusted service: {domain}"
    if domain.endswith(".edu"):
        return f"Educational institution: {domain}"
    return f"Domain: {domain}"
