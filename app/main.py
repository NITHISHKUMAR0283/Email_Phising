
 
import os
from datetime import datetime

# Load environment variables FIRST before any imports that use them
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

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
from .schemas import (
    ChatRequest, ChatResponse, PrivacyEventType, PrivacyLogEntry
)
from .security_services import (
    generate_chatbot_response, generate_flagged_report, export_report_to_csv,
    append_privacy_log, get_privacy_log
)



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
    """Backend startup - load all models on initialization."""
    global model, tokenizer
    
    print("\n🚀 Backend starting up...")
    print("📦 Loading ML models...")
    
    try:
        # Load main phishing detection model
        print("   ├─ Loading phishing detection model...")
        model, tokenizer = load_model()
        print("   ├─ ✅ Phishing model loaded")
        
        # Load ensemble models (phishing engine)
        print("   ├─ Loading ensemble models...")
        load_all_models()
        print("   ├─ ✅ Ensemble models loaded")
        
        # Test Groq API connection
        print("   ├─ Testing Groq API connection...")
        from .grok_analysis import GROK_API_KEY, GROK_ENABLED
        if GROK_ENABLED:
            print(f"   ├─ ✅ Groq API enabled (using single key)")
            print(f"   ├─ Key: {GROK_API_KEY[:20]}...{GROK_API_KEY[-10:]}")
        else:
            print("   ├─ ⚠️  Groq API disabled (will use heuristics fallback)")
        
        print("   └─ Models initialization complete!")
        print("\n✅ Backend ready on http://localhost:8000")
        print("✅ All models loaded and ready to use")
        print("✅ Using single Groq API key (fast & simple)\n")
        
    except Exception as e:
        print(f"\n❌ ERROR during model loading: {str(e)}")
        print("⚠️  Backend will attempt to load models on-demand\n")
        raise

print("Backend initializing...")

@app.get("/health")
def health_check():
    """Check backend health and model status."""
    global model, tokenizer
    
    from .grok_analysis import GROK_ENABLED, GROK_API_KEY
    
    return {
        "status": "🟢 online",
        "models_loaded": model is not None and tokenizer is not None,
        "phishing_model": "✅ loaded" if model else "❌ not loaded",
        "tokenizer": "✅ loaded" if tokenizer else "❌ not loaded",
        "groq_api": {
            "enabled": GROK_ENABLED,
            "key_preview": f"{GROK_API_KEY[:20]}...{GROK_API_KEY[-10:]}" if GROK_API_KEY else "N/A",
            "mode": "Single API Key (No Rotation)"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

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
        "url_analysis": engine_result.get("url_analysis"),  # Detailed URL analysis
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
        "signal_agreement": engine_result["signal_agreement"],
        "url_analysis": engine_result.get("url_analysis")  # Detailed URL analysis
    }


# ============================================================================
# NEW ENDPOINTS: Chatbot, Report Generation, Privacy Logging
# ============================================================================

@app.post("/api/chat-groq", response_model=ChatResponse)
async def chat_with_groq(request: ChatRequest):
    """
    Chatbot endpoint using Groq LLM.
    
    Maintains conversation history and supports contextual queries about emails,
    risks, and inbox security statistics.
    """
    try:
        # Log privacy event
        append_privacy_log(
            event=PrivacyEventType.CHAT_QUERY,
            action=f"Chat query submitted: '{request.query[:50]}...'",
            details={"query": request.query, "has_context": request.context is not None}
        )
        
        # Generate response via Groq
        response = await generate_chatbot_response(request)
        return response
    
    except Exception as e:
        return ChatResponse(
            message=f"Error processing chat: {str(e)}",
            conversationHistory=request.conversationHistory
        )


@app.get("/api/reports/flagged")
def get_flagged_report(flagged_emails: Optional[str] = None):
    """
    Generate report of flagged (high-risk) emails.
    
    Query params:
    - flagged_emails: JSON string of flagged email list (optional, demo data if empty)
    
    Returns: FlaggedReportData with top 5 and all flagged emails
    """
    import json
    
    # Parse flagged emails from query or use demo data
    if flagged_emails:
        try:
            emails = json.loads(flagged_emails)
        except:
            emails = []
    else:
        # Demo data for testing
        emails = []
    
    # Generate report
    report = generate_flagged_report(emails)
    
    # Log privacy event
    append_privacy_log(
        event=PrivacyEventType.REPORT_GENERATED,
        action=f"Flagged report generated with {report.totalFlagged} emails",
        details={"totalFlagged": report.totalFlagged, "topRisksCount": len(report.topRisks)}
    )
    
    return report.dict()


@app.get("/api/reports/flagged/download")
def download_flagged_report(flagged_emails: Optional[str] = None):
    """
    Download flagged emails as CSV.
    
    Returns CSV file content
    """
    import json
    from fastapi.responses import PlainTextResponse
    
    # Parse flagged emails
    if flagged_emails:
        try:
            emails = json.loads(flagged_emails)
        except:
            emails = []
    else:
        emails = []
    
    # Generate report and convert to CSV
    report = generate_flagged_report(emails)
    csv_content = export_report_to_csv(report)
    
    # Log privacy event
    append_privacy_log(
        event=PrivacyEventType.EXPORT_DATA,
        action="Flagged report exported to CSV",
        details={"emailCount": report.totalFlagged}
    )
    
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=flagged_emails_report.csv"}
    )


@app.post("/api/audit/privacy-log")
def log_privacy_event(
    event: PrivacyEventType,
    action: str,
    userId: Optional[str] = "anonymous",
    emailId: Optional[str] = None,
    details: Optional[Dict] = None
):
    """
    Log a privacy/audit event.
    
    Args:
    - event: Type of event (chat_query, report_generated, email_viewed, api_call, export_data)
    - action: Human-readable description of action
    - userId: User or session ID
    - emailId: Associated email ID if applicable
    - details: Additional context dict
    
    Returns: PrivacyLogResponse with success and entry ID
    """
    result = append_privacy_log(
        event=event,
        action=action,
        userId=userId,
        emailId=emailId,
        details=details
    )
    return result.dict()


@app.get("/api/audit/privacy-log")
def get_privacy_log_entries():
    """
    Retrieve full privacy log.
    
    Returns: List of privacy log entries
    """
    log_entries = get_privacy_log()
    return [entry.dict() for entry in log_entries]



