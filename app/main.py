
import os
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .gmail_oauth import router as gmail_router
from pydantic import BaseModel
from typing import List, Dict, Optional
from .model import load_model, predict_phishing
from .heuristics import analyze_heuristics
from .utils import combine_signals, extract_highlighted_tokens
from .quiz import generate_quiz
from datetime import datetime



app = FastAPI(title="PhishGuard AI Backend")
app.include_router(gmail_router)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load model and tokenizer at startup
model, tokenizer = load_model()
print("Model loaded, backend ready.")

class AnalyzeEmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    urls: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None



@app.post("/analyze-email")
def analyze_email(req: AnalyzeEmailRequest):
    model_probs = predict_phishing(model, tokenizer, req.email_text)
    phishing_prob = model_probs["phishing"]
    heuristics = analyze_heuristics(req.email_text, req.sender, req.urls, req.headers)
    result = combine_signals(phishing_prob, heuristics)
    highlighted = extract_highlighted_tokens(req.email_text, heuristics)
    quiz = generate_quiz(req.email_text, highlighted)
    timestamp = datetime.utcnow().isoformat()
    output = {
        "risk_score": result["risk_score"],
        "highlighted_tokens": highlighted,
        "heuristics": heuristics["signals"],
        "quiz": quiz,
        "timestamp": timestamp,
        "subject": req.subject or "",
        "sender": req.sender or "",
        "email_text": req.email_text,
        "urls": req.urls or [],
        "headers": req.headers or {},
    }
    # Log to local JSON file
    log_path = "phishing_logs.json"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            logs = json.load(f)
    else:
        logs = []
    logs.append(output)
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
    return output

# Endpoint to fetch logs
@app.get("/logs")
def get_logs():
    log_path = "phishing_logs.json"
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as f:
            logs = json.load(f)
        return logs
    return []
