
 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .gmail_oauth import router as gmail_router
from pydantic import BaseModel
from typing import List, Dict, Optional
from .model import load_model, predict_phishing
from .heuristics import analyze_heuristics
from .utils import combine_signals, extract_highlighted_tokens
from .quiz import generate_quiz
from .phishing_engine import load_all_models
from datetime import datetime



app = FastAPI(title="PhishGuard AI Backend")
app.include_router(gmail_router)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://email-phising.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load models eagerly on startup
model, tokenizer = None, None

@app.on_event("startup")
async def startup_event():
    """Load all models when backend starts."""
    print("\n🚀 Backend starting... Loading models...")
    load_all_models()
    global model, tokenizer
    model, tokenizer = load_model()
    print("✅ Backend ready! All models loaded.\n")

print("Backend initializing...")

class AnalyzeEmailRequest(BaseModel):
    email_text: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    urls: Optional[List[str]] = None
    headers: Optional[Dict[str, str]] = None



@app.post("/analyze-email")
def analyze_email(req: AnalyzeEmailRequest):
    global model, tokenizer
    
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
    return output


