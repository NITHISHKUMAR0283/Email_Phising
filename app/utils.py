"""
Utility functions: combine model and heuristics, explainable AI
"""
from typing import Dict, List

def combine_signals(model_prob: float, heuristics: Dict) -> Dict:
    """
    Combine model probability and heuristics to output is_phishing and risk_score.
    """
    score = model_prob
    if heuristics["signals"]:
        score += 0.2  # Boost if heuristics found
    if score > 0.7:
        return {"is_phishing": True, "risk_score": "High"}
    elif score > 0.4:
        return {"is_phishing": True, "risk_score": "Medium"}
    else:
        return {"is_phishing": False, "risk_score": "Low"}

def extract_highlighted_tokens(email_text: str, heuristics: Dict) -> List[str]:
    """
    Extract suspicious tokens for explainable AI (from heuristics and keywords).
    """
    tokens = []
    for signal in heuristics["signals"]:
        if signal.startswith("Suspicious phrase: "):
            tokens.append(signal.replace("Suspicious phrase: ", ""))
    return tokens
