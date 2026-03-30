
 
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
from .grok_analysis import generate_grok_analysis
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
    """Fast analysis without Grok - for batch email loading."""
    global model, tokenizer
    
    model_probs = predict_phishing(model, tokenizer, req.email_text)
    phishing_prob = model_probs["phishing"]
    heuristics = analyze_heuristics(req.email_text, req.sender, req.urls, req.headers)
    result = combine_signals(phishing_prob, heuristics)
    highlighted = extract_highlighted_tokens(req.email_text, heuristics)
    quiz = generate_quiz(req.email_text, highlighted)
    timestamp = datetime.utcnow().isoformat()
    
    # NO Grok here - only return basic analysis for fast batch loading
    output = {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "is_phishing": result["is_phishing"],
        "highlighted_tokens": highlighted,
        "heuristics": heuristics["signals"],
        "quiz": quiz,
        "timestamp": timestamp,
        "subject": req.subject or "",
        "sender": req.sender or "",
        "email_text": req.email_text,
        "urls": req.urls or [],
        "headers": req.headers or {},
        "ai_analysis": None,  # Will be filled by separate Grok endpoint
    }
    return output


@app.post("/analyze-email-groq")
def analyze_email_groq(req: AnalyzeEmailRequest):
    """Call Groq AI analysis ONLY when user views a specific email (on-demand).
    Returns the AI-generated risk score as the PRIMARY score."""
    global model, tokenizer
    
    # Quick heuristics analysis (reuse for context)
    heuristics = analyze_heuristics(req.email_text, req.sender, req.urls, req.headers)
    model_probs = predict_phishing(model, tokenizer, req.email_text)
    result = combine_signals(model_probs["phishing"], heuristics)
    
    # Call Grok for AI explanation + AI-GENERATED RISK SCORE (on-demand)
    grok_analysis = generate_grok_analysis(
        email_text=req.email_text,
        subject=req.subject or "",
        sender=req.sender or "",
        urls=req.urls or [],
        heuristics=heuristics.get("signals", {}),
        risk_score=result["risk_score"]
    )
    
    # Use Groq's risk_score as PRIMARY score (override heuristic score)
    groq_risk_score = grok_analysis.get("risk_score", result["risk_score"])
    
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
        "heuristic_score": result["risk_score"]  # Keep heuristic for reference
    }


