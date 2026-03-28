"""
Offline LLM Reasoning Module (placeholder)
"""
from typing import Optional

def generate_reasoning(email_text: str, url: Optional[str] = None, headers: Optional[dict] = None) -> str:
    """
    Use local LLM to generate a short reasoning snippet explaining why an email is suspicious.
    """
    # TODO: Integrate with local LLM (Ollama, llama-cpp-python, etc.)
    if url and "ip" in url:
        return "The link points to an IP address, which is often used in phishing campaigns."
    if headers and headers.get("From", "").endswith(".ru"):
        return "The sender domain is newly registered and uses a suspicious TLD (.ru)."
    if "urgent" in email_text.lower():
        return "The email creates urgency, a common phishing tactic."
    return "No strong phishing indicators detected by LLM."
