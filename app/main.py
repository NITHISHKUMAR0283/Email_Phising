
 
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .gmail_oauth import router as gmail_router
from pydantic import BaseModel
from typing import List, Dict, Optional
from .model import load_model, predict_phishing
from .heuristics import analyze_heuristics
from .utils import combine_signals, extract_highlighted_tokens
from .quiz import generate_quiz
from .phishing_engine import load_all_models, phishing_engine
from .grok_analysis import generate_grok_analysis
from datetime import datetime
import os

# Try to load environment variables from .env file (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # If dotenv not installed, just use environment variables directly
    pass



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
    """Fast analysis without Grok - for batch email loading.
    
    Uses NEW phishing_engine with ensemble voting instead of old combine_signals.
    """
    global model, tokenizer
    
    # NEW: Use phishing_engine for better detection
    email_data = {
        "subject": req.subject or "",
        "body": req.email_text,
        "sender": req.sender or "",
        "urls": req.urls or [],
        "headers": req.headers or {}
    }
    
    engine_result = phishing_engine(email_data)
    
    # Map to old format for frontend compatibility
    is_phishing = engine_result["risk_level"] == "HIGH"
    if engine_result["risk_level"] == "HIGH":
        risk_score = max(0.65, engine_result["final_score"])  # Ensure HIGH is clear
    elif engine_result["risk_level"] == "MEDIUM":
        risk_score = max(0.40, engine_result["final_score"])
    else:
        risk_score = min(0.35, engine_result["final_score"])
    
    # Extract highlighted phrases
    highlighted = engine_result["highlight"]["phrases"] + engine_result["highlight"]["urls"]
    
    quiz = generate_quiz(req.email_text, highlighted)
    timestamp = datetime.utcnow().isoformat()
    
    # Return enhanced results with new fields
    output = {
        "risk_score": engine_result["final_score"],
        "risk_level": engine_result["risk_level"],
        "is_phishing": is_phishing,
        "highlighted_tokens": highlighted,
        "heuristics": engine_result["reasons"],
        "quiz": quiz,
        "timestamp": timestamp,
        "subject": req.subject or "",
        "sender": req.sender or "",
        "email_text": req.email_text,
        "urls": req.urls or [],
        "headers": req.headers or {},
        "ai_analysis": None,  # Will be filled by separate Grok endpoint
        # NEW: Additional fields from ensemble voting
        "confidence": engine_result["confidence"],
        "signal_agreement": engine_result["signal_agreement"],
        "is_whitelisted": engine_result["is_whitelisted"],
        "components": engine_result["components"],
    }
    return output


@app.post("/analyze-email-groq")
def analyze_email_groq(req: AnalyzeEmailRequest):
    """Call Groq AI analysis ONLY when user views a specific email (on-demand).
    Uses NEW phishing_engine for detection context."""
    global model, tokenizer
    
    # NEW: Use phishing_engine for better context
    email_data = {
        "subject": req.subject or "",
        "body": req.email_text,
        "sender": req.sender or "",
        "urls": req.urls or [],
        "headers": req.headers or {}
    }
    
    engine_result = phishing_engine(email_data)
    
    # Call Grok for AI explanation + AI-GENERATED RISK SCORE (on-demand)
    grok_analysis = generate_grok_analysis(
        email_text=req.email_text,
        subject=req.subject or "",
        sender=req.sender or "",
        urls=req.urls or [],
        heuristics=engine_result["reasons"],  # Use engine reasons instead
        risk_score=engine_result["final_score"]
    )
    
    # Use Groq's risk_score as PRIMARY score (override phishing_engine score)
    groq_risk_score = grok_analysis.get("risk_score", engine_result["final_score"])
    
    # Determine risk level from Groq score
    if groq_risk_score >= 0.75:
        risk_level = "High"
    elif groq_risk_score >= 0.50:
        risk_level = "Medium"
    else:
        risk_level = "Low"
    
    return {
        "ai_analysis": grok_analysis,
        "risk_score": groq_risk_score,  # AI-GENERATED SCORE (PRIMARY)
        "risk_level": risk_level,
        "engine_score": engine_result["final_score"],  # Phishing engine score for reference
        "confidence": engine_result["confidence"],
        "signal_agreement": engine_result["signal_agreement"]
    }


