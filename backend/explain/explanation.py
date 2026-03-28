"""
Explainable AI: Human-readable explanation generator
"""
from typing import List

def generate_explanation(email_text: str, highlighted_tokens: List[str]) -> str:
    """
    Generate a human-readable explanation for why the email is suspicious.
    """
    if not highlighted_tokens:
        return "No suspicious patterns detected."
    return (
        f"The email contains suspicious phrases: {', '.join(highlighted_tokens)}. "
        "These are commonly used in phishing attempts to create urgency or trick users."
    )
