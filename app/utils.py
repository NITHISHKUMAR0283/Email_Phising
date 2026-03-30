
from typing import Dict, List

def combine_signals(model_prob: float, heuristics: Dict) -> Dict:
    """
    Combine model probability and heuristics to output is_phishing and risk_score.
    Returns a dict with is_phishing (bool) and risk_score (float 0-1).
    """
    # Use model probability as primary signal
    score = model_prob
    
    # Add heuristic risk if available
    url_risks = [url.get("risk_score", 0) for url in heuristics.get("url_details", [])]
    if url_risks:
        # Average URL risk score (0-100 scale), convert to 0-1
        avg_url_risk = sum(url_risks) / len(url_risks) / 100.0
        # Weight: 70% model, 30% heuristics
        score = (score * 0.7) + (avg_url_risk * 0.3)
    
    # Ensure score is in 0-1 range
    score = min(max(score, 0.0), 1.0)
    
    # Determine risk level
    if score >= 0.75:
        risk_level = "High"
    elif score >= 0.50:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {"is_phishing": score >= 0.5, "risk_score": score, "risk_level": risk_level}

def extract_highlighted_tokens(email_text: str, heuristics: Dict) -> List[str]:
    """
    Extract suspicious tokens for explainable AI (from heuristics and keywords).
    Returns a list of risky tokens/phrases to highlight in the frontend.
    """
    tokens = []
    for signal in heuristics["signals"]:
        if signal.startswith("Suspicious phrase: "):
            tokens.append(signal.replace("Suspicious phrase: ", ""))
    return tokens
