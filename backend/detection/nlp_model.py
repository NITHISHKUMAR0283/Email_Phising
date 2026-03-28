"""
DistilBERT-based NLP phishing detection (placeholder for real model)
"""
from typing import Tuple

def predict_nlp_phishing(email_text: str) -> Tuple[float, str]:
    """
    Returns (score, reason) for phishing likelihood using NLP.
    """
    # TODO: Replace with real DistilBERT inference
    score = 0.8 if "urgent" in email_text.lower() else 0.2
    reason = "Detected urgent language" if score > 0.7 else "No urgent language detected"
    return score, reason
