"""
Ensemble Phishing Detection Module
Combines NLP (DistilBERT), URL/domain, and header analysis.
"""
from typing import Dict, Any

# Placeholder imports for actual models
# from .nlp_model import predict_nlp_phishing
# from .url_analyzer import analyze_url
# from .header_analyzer import analyze_headers

def ensemble_detect(email_text: str, url: str = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Run ensemble phishing detection on email content, URL, and headers.
    Returns dict with is_phishing, risk_score, and reason.
    """
    # --- NLP Model (DistilBERT) ---
    nlp_score = 0.8 if "urgent" in email_text.lower() else 0.2  # Placeholder
    nlp_reason = "Detected urgent language" if nlp_score > 0.7 else "No urgent language detected"

    # --- URL/Domain Analysis ---
    url_score = 0.7 if url and "ip" in url else 0.1  # Placeholder
    url_reason = "Link points to suspicious IP" if url_score > 0.5 else "URL appears safe"

    # --- Header Analysis ---
    header_score = 0.6 if headers and headers.get("From", "").endswith(".ru") else 0.1  # Placeholder
    header_reason = "Sender domain is .ru" if header_score > 0.5 else "Sender domain appears safe"

    # --- Ensemble ---
    total_score = (nlp_score + url_score + header_score) / 3
    if total_score > 0.7:
        risk = "High"
    elif total_score > 0.4:
        risk = "Medium"
    else:
        risk = "Low"
    is_phishing = total_score > 0.5
    reason = f"{nlp_reason}; {url_reason}; {header_reason}"
    return {
        "is_phishing": is_phishing,
        "risk_score": risk,
        "reason": reason,
        "scores": {
            "nlp": nlp_score,
            "url": url_score,
            "header": header_score
        }
    }
