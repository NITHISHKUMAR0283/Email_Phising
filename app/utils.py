
from typing import Dict, List

def combine_signals(model_prob: float, heuristics: Dict) -> Dict:
    """
    Combine model probability and heuristics to output is_phishing and risk_score.
    Returns a dict with is_phishing (bool) and risk_score (str: Low/Medium/High).
    """
    score = model_prob
    # Updated thresholds: >=0.9991 High, >0.9690 Medium, else Safe (Low)
    if score >= 0.9991:
        return {"is_phishing": True, "risk_score": "High"}
    elif score > 0.9690:
        return {"is_phishing": True, "risk_score": "Medium"}
    else:
        return {"is_phishing": False, "risk_score": "Safe"}

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
