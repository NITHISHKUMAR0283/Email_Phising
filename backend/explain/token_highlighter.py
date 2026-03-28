"""
Explainable AI: Token Highlighter
Highlights suspicious tokens in email text.
"""
from typing import List

SUSPICIOUS_TOKENS = [
    "urgent", "click", "reset your password", "verify", "account locked", "login", "update", "immediately", "action required"
]

def highlight_tokens(email_text: str) -> List[str]:
    """
    Returns a list of suspicious tokens found in the email text.
    """
    found = []
    text_lower = email_text.lower()
    for token in SUSPICIOUS_TOKENS:
        if token in text_lower:
            found.append(token)
    return found
