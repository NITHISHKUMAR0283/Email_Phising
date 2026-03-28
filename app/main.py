"""
PhishGuard AI - FastAPI Backend for Offline Phishing Detection
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional
from model import load_model, predict_phishing
from heuristics import analyze_heuristics
from utils import combine_signals, extract_highlighted_tokens


app = FastAPI(title="PhishGuard AI Backend")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or ["http://localhost:5173"] for stricter security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model and tokenizer at startup
model, tokenizer = load_model()
print("Model loaded, backend ready.")

class AnalyzeEmailRequest(BaseModel):
    email_text: str
    sender: Optional[str] = None
    urls: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None


@app.post("/analyze-email")
def analyze_email(req: AnalyzeEmailRequest):
    # Model prediction
    model_probs = predict_phishing(model, tokenizer, req.email_text)
    phishing_prob = model_probs["phishing"]
    # Heuristics
    heuristics = analyze_heuristics(req.email_text, req.sender, req.urls, req.headers)
    # Combine
    result = combine_signals(phishing_prob, heuristics)
    # Explainable AI
    highlighted = extract_highlighted_tokens(req.email_text, heuristics)
    return {
        "is_phishing": result["is_phishing"],
        "risk_score": result["risk_score"],
        "model_probs": model_probs,
        "highlighted_tokens": highlighted,
        "heuristics": heuristics["signals"]
    }
