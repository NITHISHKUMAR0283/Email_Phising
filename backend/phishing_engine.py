"""
Multi-signal phishing detection engine for hackathon demo.
Combines URL, domain, intent, and text analysis for explainable risk scoring.
"""
import re
from urllib.parse import urlparse
from typing import List, Dict, Any
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch


# Preload Hugging Face models for each signal
URL_MODEL_ID = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
DOMAIN_MODEL_ID = "CrabInHoney/domainbert-tiny-v1-domain-phishing-classifier"
INTENT_MODEL_ID = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
TEXT_MODEL_ID = "CrabInHoney/emailbert-tiny-v1-phishing-classifier"

url_tokenizer = AutoTokenizer.from_pretrained(URL_MODEL_ID)
url_model = AutoModelForSequenceClassification.from_pretrained(URL_MODEL_ID)

domain_tokenizer = AutoTokenizer.from_pretrained(DOMAIN_MODEL_ID)
domain_model = AutoModelForSequenceClassification.from_pretrained(DOMAIN_MODEL_ID)

intent_tokenizer = AutoTokenizer.from_pretrained(INTENT_MODEL_ID)
intent_model = AutoModelForSequenceClassification.from_pretrained(INTENT_MODEL_ID)

text_tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL_ID)
text_model = AutoModelForSequenceClassification.from_pretrained(TEXT_MODEL_ID)

# --- Step 2: URL Analysis ---
def analyze_url(urls: List[str]) -> (float, List[str], List[str]):
    """
    Analyze URLs using the phishing classifier model.
    Returns max score, suspicious URLs, and explanations.
    """
    if not urls:
        return 0.0, [], []
    scores = []
    suspicious = []
    explanations = []
    for url in urls:
        inputs = url_tokenizer(url, return_tensors="pt", truncation=True, max_length=64)
        with torch.no_grad():
            outputs = url_model(**inputs)
            prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()  # phishing prob
        scores.append(prob)
        if prob > 0.7:
            suspicious.append(url)
            explanations.append(f"Suspicious URL detected: {url}")
        elif prob > 0.4:
            explanations.append(f"Potentially risky URL: {url}")
    return max(scores), suspicious, explanations

# --- Step 3: Domain Analysis ---
def extract_domain(email_or_url: str) -> str:
    """Extract domain from email or URL."""
    if '@' in email_or_url:
        return email_or_url.split('@')[-1].lower()
    try:
        return urlparse(email_or_url).netloc.lower()
    except Exception:
        return ""

def analyze_domain(sender: str, urls: List[str]) -> (float, List[str]):
    """
    Use a domain phishing classifier model on sender and URL domains.
    Returns max score, explanations.
    """
    explanations = []
    sender_domain = extract_domain(sender)
    url_domains = [extract_domain(u) for u in urls]
    scores = []
    for domain in [sender_domain] + url_domains:
        if not domain:
            continue
        inputs = domain_tokenizer(domain, return_tensors="pt", truncation=True, max_length=32)
        with torch.no_grad():
            outputs = domain_model(**inputs)
            prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
        scores.append(prob)
        if prob > 0.7:
            explanations.append(f"Suspicious domain detected: {domain}")
        elif prob > 0.4:
            explanations.append(f"Potentially risky domain: {domain}")
    return (max(scores) if scores else 0.0), explanations

# --- Step 4: Intent Detection ---
INTENT_KEYWORDS = [
    "verify your account",
    "click here",
    "urgent action required",
    "update your password",
    "login now",
    "confirm identity"
]
def detect_intent(text: str) -> (float, List[str], List[str]):
    """
    Use an intent/spam classifier model for phishing intent.
    Returns score, matched phrases (if any), explanations.
    """
    inputs = intent_tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
    with torch.no_grad():
        outputs = intent_model(**inputs)
        prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
    explanations = []
    matches = []
    if prob > 0.7:
        explanations.append("Phishing/social engineering intent detected.")
        matches.append("phishing intent")
    elif prob > 0.4:
        explanations.append("Possible suspicious intent detected.")
    return prob, matches, explanations

# --- Step 5: Text Classification (simple rule-based) ---
THREAT_WORDS = ["suspend", "deactivate", "immediately", "threat", "compromise", "risk", "urgent", "action required"]
SOCIAL_ENGINEERING = ["gift", "prize", "winner", "congratulations", "limited time", "exclusive"]
def analyze_text(text: str) -> (float, List[str]):
    """
    Use a phishing email classifier model for text scoring.
    Returns score and explanations.
    """
    inputs = text_tokenizer(text, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        outputs = text_model(**inputs)
        prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
    explanations = []
    if prob > 0.7:
        explanations.append("Phishing/spam content detected in email text.")
    elif prob > 0.4:
        explanations.append("Potentially suspicious content in email text.")
    return prob, explanations

# --- Step 6: Final Scoring ---
def compute_final_score(url_score, domain_score, intent_score, text_score):
    return (
        0.4 * url_score +
        0.25 * domain_score +
        0.2 * intent_score +
        0.15 * text_score
    )

# --- Step 7-8: Main Engine ---
def phishing_engine(email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry: takes parsed email dict, returns explainable phishing risk result.
    """
    subject = email.get("subject", "")
    body = email.get("body", "")
    sender = email.get("sender", "")
    urls = email.get("urls", [])
    # URL analysis
    url_score, suspicious_urls, url_expl = analyze_url(urls)
    # Domain analysis
    domain_score, domain_expl = analyze_domain(sender, urls)
    # Intent detection
    intent_score, matched_phrases, intent_expl = detect_intent(subject + "\n" + body)
    # Text classification
    text_score, text_expl = analyze_text(subject + "\n" + body)
    # Final score
    final_score = compute_final_score(url_score, domain_score, intent_score, text_score)
    # Risk level
    if final_score > 0.75:
        risk_level = "HIGH"
    elif final_score > 0.45:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    # Reasons
    reasons = url_expl + domain_expl + intent_expl + text_expl
    # Highlight
    highlight = {
        "urls": suspicious_urls,
        "phrases": matched_phrases
    }
    return {
        "risk_level": risk_level,
        "final_score": round(final_score, 2),
        "components": {
            "url_score": round(url_score, 2),
            "domain_score": round(domain_score, 2),
            "intent_score": round(intent_score, 2),
            "text_score": round(text_score, 2)
        },
        "reasons": reasons,
        "highlight": highlight
    }

# Example usage (for testing):
if __name__ == "__main__":
    sample_email = {
        "subject": "Urgent action required: verify your account",
        "body": "Click here to update your password immediately. http://fake-paypal-login.xyz",
        "sender": "security@paypal.com",
        "urls": ["http://fake-paypal-login.xyz"]
    }
    import json
    print(json.dumps(phishing_engine(sample_email), indent=2))
