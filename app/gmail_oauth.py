import os
import sys
import base64
import re
import time
import json
import html
from html.parser import HTMLParser
from fastapi import APIRouter, Request, Response
from fastapi import Cookie
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .phishing_engine import phishing_engine
from .grok_analysis import generate_grok_analysis
from .heuristics import analyze_heuristics
from .url_grok_analyzer import analyze_urls_with_grok
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to Python path to import domain folder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from domain.header_analyzer import analyze_headers as analyze_headers_domain
from domain.risk_engine import compute_risk

CLIENT_ID = "685356081512-k89ps7iino08oqlc2bipvt73eqar3apo.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://localhost:8000/oauth2callback"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

router = APIRouter()
user_tokens = {}
code_verifiers = {}

def get_flow():
    return Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

@router.get("/login")
def login(response: Response):
    flow = get_flow()
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", code_challenge_method="S256")
    # Store code_verifier in a cookie (for demo; use secure session in production)
    response = RedirectResponse(auth_url)
    response.set_cookie(key="code_verifier", value=flow.code_verifier, httponly=True)
    return response

@router.get("/oauth2callback")
def oauth2callback(request: Request, code_verifier: str = Cookie(None)):
    code = request.query_params.get("code")
    flow = get_flow()
    # Use code_verifier from cookie
    flow.fetch_token(code=code, code_verifier=code_verifier)
    credentials = flow.credentials
    user_tokens["access_token"] = credentials.token
    # Clear the code_verifier cookie
    # Redirect with token as query param so frontend can save to localStorage
    response = RedirectResponse(f"http://localhost:5173/?token={credentials.token}")
    response.delete_cookie("code_verifier")
    return response

@router.get("/check-auth")
def check_auth(request: Request):
    """Check if user is authenticated. Accept token from header or query param."""
    # Try to get token from Authorization header first
    auth_header = request.headers.get("Authorization", "")
    token = None
    
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix
    else:
        # Fallback to in-memory tokens (for session persistence)
        token = user_tokens.get("access_token")
    
    if token:
        return JSONResponse({"authenticated": True}, status_code=200)
    else:
        return JSONResponse({"authenticated": False}, status_code=401)

@router.get("/logout")
def logout(response: Response):
    """Logout user by clearing access token."""
    user_tokens.clear()
    response = RedirectResponse("http://localhost:5173/")
    return response

def extract_email_body(payload: Dict[str, Any]) -> str:
    """Extract email body from payload - handles plain text, HTML, and nested parts."""
    body = ""
    
    def clean_html(html_text: str) -> str:
        """Clean HTML content to readable text."""
        # Remove style and script tags completely
        html_text = re.sub(r'<style[^>]*>.*?</style>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
        html_text = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
        
        # Decode HTML entities
        html_text = html.unescape(html_text)
        
        # Remove all remaining HTML tags
        html_text = re.sub(r'<[^>]+>', '\n', html_text)
        
        # Replace multiple whitespace with single space/newline
        html_text = re.sub(r'\n\s*\n', '\n', html_text)  # Remove blank lines
        html_text = re.sub(r' +', ' ', html_text)  # Remove multiple spaces
        
        # Clean up common artifacts
        html_text = re.sub(r'&nbsp;', ' ', html_text)
        html_text = re.sub(r'[\t\r]+', '', html_text)
        
        # Remove leading/trailing whitespace each line
        lines = [line.strip() for line in html_text.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def extract_from_parts(parts):
        """Recursively extract body from email parts."""
        for part in parts:
            mime_type = part.get("mimeType", "")
            
            # Try to extract data from current part
            if mime_type == "text/plain":
                data = part.get("body", {}).get("data", "")
                if data:
                    return base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
            
            elif mime_type == "text/html":
                data = part.get("body", {}).get("data", "")
                if data:
                    html_text = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
                    return clean_html(html_text)
            
            # If part has nested parts, recurse
            if "parts" in part:
                result = extract_from_parts(part["parts"])
                if result:
                    return result
        
        return None
    
    # Handle multipart emails
    if "parts" in payload:
        body = extract_from_parts(payload["parts"]) or ""
    else:
        # Single part email
        data = payload.get("body", {}).get("data", "")
        if data:
            text = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
            # Check if it looks like HTML
            if '<' in text and '>' in text:
                body = clean_html(text)
            else:
                body = text
    
    return body or "(No email body content available)"

def process_email_message(access_token: str, msg: Dict[str, Any]) -> Dict[str, Any] | None:
    """Process a single email message (heuristics + ML + Groq AI).
    Creates a fresh Gmail service per thread for thread-safety.
    Returns result with timing info, or None if parse fails.
    """
    fetch_start = time.time()
    
    try:
        # Create a fresh service for this thread (thread-safe)
        creds = Credentials(token=access_token)
        service = build("gmail", "v1", credentials=creds)
        
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        fetch_time = (time.time() - fetch_start) * 1000
        
        if not msg_data or "payload" not in msg_data:
            return None
        
        headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
        subject = headers.get("Subject", "")
        sender = headers.get("From", "")
        body = extract_email_body(msg_data.get("payload", {}))
        
        # Extract URLs from body (http, https, and bare domains)
        urls_with_scheme = re.findall(r'https?://\S+', body) if body else []
        
        # Also find bare domains that were missed (optional: domain.com patterns)
        # For now, only use explicitly stated URLs
        urls = urls_with_scheme
        
        # 🔐 HEADER ANALYSIS: SPF/DKIM/DMARC + Spoofing Detection (using domain folder)
        header_analysis_start = time.time()
        header_result = analyze_headers_domain(headers)  # Pass headers dict directly
        header_analysis_time = (time.time() - header_analysis_start) * 1000
        header_risk_score = header_result.header_risk_score if hasattr(header_result, 'header_risk_score') else 0.0
        
        # Extract header analysis details for display
        header_details = {
            "spf": header_result.spf if hasattr(header_result, 'spf') else "none",
            "dkim": header_result.dkim if hasattr(header_result, 'dkim') else "none",
            "dmarc": header_result.dmarc if hasattr(header_result, 'dmarc') else "none",
            "is_spoofed": header_result.is_spoofed if hasattr(header_result, 'is_spoofed') else False,
            "spoofing_reasons": header_result.spoofing_reasons if hasattr(header_result, 'spoofing_reasons') else [],
            "hops": header_result.hops if hasattr(header_result, 'hops') else 0,
            "originating_ip": header_result.originating_ip if hasattr(header_result, 'originating_ip') else None,
        }
        
        # Run phishing_engine (heuristics + ML) with timing
        model_start = time.time()
        email_obj = {
            "subject": subject,
            "body": body,
            "sender": sender,
            "urls": urls,
            "headers": headers  # Pass headers for header authentication scoring
        }
        result = phishing_engine(email_obj)
        model_time = (time.time() - model_start) * 1000
        
        # 🎯 DETACHED: URL Grok Analysis (code kept but not used in scoring yet)
        # Will be re-enabled when logic is verified
        url_analysis_start = time.time()
        url_analysis = {}
        if urls:
            # TODO: Re-enable URL Grok analysis
            pass
            # url_analysis = analyze_urls_with_grok(urls)
        url_analysis_time = (time.time() - url_analysis_start) * 1000
        
        # Run Groq AI analysis with timing
        groq_start = time.time()
        ai_analysis = generate_grok_analysis(
            email_text=body,
            subject=subject,
            sender=sender,
            urls=urls,
            heuristics=result.get("components", {}),
            risk_score=result.get("final_score", 0.5)
        )
        groq_time_ms = (time.time() - groq_start) * 1000
        
        # ⭐ USE DOMAIN FOLDER'S RISK ENGINE: Score mapping
        # NLP = Grok AI analysis (semantic understanding of threat)
        # Link = Heuristic score (URL + domain ML models)
        # Header = Email header authentication + spoofing detection
        # Visual = 0 (not implemented yet)
        nlp_score = ai_analysis.get("risk_score", 0.5)
        link_score = result.get("final_score", 0.5)
        visual_score = 0.0  # TODO: Implement logo/brand visual analysis
        
        # Use domain folder's risk engine for weighted scoring
        risk_report = compute_risk(
            nlp_score=nlp_score,
            link_score=link_score,
            header_score=header_risk_score,
            visual_score=visual_score,
            weights={
                "nlp": 0.35,
                "link": 0.25,
                "header": 0.30,
                "visual": 0.10
            },
            details={
                "header_details": header_details,
                "heuristic_components": result.get("components"),
            }
        )
        
        return {
            "id": msg["id"],
            "subject": subject,
            "sender": sender,
            "risk_level": risk_report.severity,  # CRITICAL, HIGH, MEDIUM, LOW, SAFE
            "final_score": risk_report.composite_score,  # ⭐ PRIMARY SCORE (0-1)
            "confidence": risk_report.confidence,  # Confidence in the assessment
            "nlp_score": nlp_score,  # Grok AI semantic analysis
            "link_score": link_score,  # URL/domain ML models
            "header_score": header_risk_score,  # Email authentication + spoofing
            "visual_score": visual_score,  # Visual/logo analysis
            "components": result.get("components"),
            "reasons": result.get("reasons"),
            "highlight": result.get("highlight"),
            "body": body,
            "timestamp": msg_data.get("internalDate", ""),
            "fetch_time_ms": round(fetch_time, 2),
            "model_time_ms": round(model_time, 2),
            "groq_time_ms": round(groq_time_ms, 2),
            "header_analysis_ms": round(header_analysis_time, 2),
            "url_analysis_ms": round(url_analysis_time, 2),
            "ai_analysis": ai_analysis,  # Groq AI analysis
            "header_analysis": header_details,  # Email header security analysis
            "header_result": header_result.to_dict() if hasattr(header_result, 'to_dict') else {},  # Full header analysis
            "url_analysis": url_analysis,  # URL analysis
            "risk_report": risk_report.to_dict()  # Full risk report from domain engine
        }
    except Exception as e:
        error_str = str(e)
        print(f"Error processing email {msg.get('id')}: {error_str[:80]}")
    
    return None

@router.get("/fetch-all-emails")
def fetch_all_emails(max_results: int = 10, token: str = None, folder: str = "INBOX"):
    """Fetch emails with phishing analysis and timing information.
    Accepts token from query param (for frontend persistence) or falls back to session tokens.
    
    Args:
        max_results: Number of emails to fetch (default 10)
        token: Gmail access token
        folder: Email folder/label - "INBOX", "SPAM", "SENT", "DRAFT" (default "INBOX")
    """
    total_start = time.time()
    
    # Use provided token or fall back to in-memory token
    access_token = token or user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Build query to fetch from specific folder/label
    query_label = f"label:{folder}" if folder else None
    
    # Fetch message list
    fetch_list_start = time.time()
    messages = service.users().messages().list(userId="me", maxResults=max_results, q=query_label).execute().get("messages", [])
    fetch_list_time_ms = (time.time() - fetch_list_start) * 1000
    
    if not messages:
        total_time_ms = (time.time() - total_start) * 1000
        return {
            "all_emails": [],
            "phishing_emails": [],
            "fetch_time_ms": round(total_time_ms, 2),
            "total_model_time_ms": 0,
            "total_emails": 0,
            "phishing_count": 0,
            "total_time_ms": round(total_time_ms, 2)
        }
    
    all_emails = []
    phishing_emails = []
    total_fetch_time_ms = fetch_list_time_ms
    total_model_time_ms = 0
    
    # Process emails sequentially
    for msg in messages:
        result = process_email_message(access_token, msg)
        if result:
            all_emails.append(result)
            total_fetch_time_ms += result.get("fetch_time_ms", 0)
            total_model_time_ms += result.get("model_time_ms", 0)
            
            # Separate phishing emails
            if result.get("risk_score") == "HIGH":
                phishing_emails.append(result)
    
    # Sort both by final_score (highest risk first)
    all_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
    phishing_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
    
    total_time_ms = (time.time() - total_start) * 1000
    
    return {
        "all_emails": all_emails,
        "phishing_emails": phishing_emails,
        "fetch_time_ms": round(total_fetch_time_ms, 2),
        "total_model_time_ms": round(total_model_time_ms, 2),
        "total_emails": len(all_emails),
        "phishing_count": len(phishing_emails),
        "total_time_ms": round(total_time_ms, 2)
    }

@router.get("/fetch-high-risk-emails")
def fetch_high_risk_emails(token: str = None, max_results: int = 20, folder: str = "INBOX"):
    """Fetch high-risk emails from specific folder. 
    Accepts token from query param or falls back to session tokens.
    
    Args:
        token: Gmail access token
        max_results: Number of emails to fetch (default 20)
        folder: Email folder/label - "INBOX", "SPAM", "SENT", "DRAFT" (default "INBOX")
    """
    # Use provided token or fall back to in-memory token
    access_token = token or user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Build query to fetch from specific folder/label
    query_label = f"label:{folder}" if folder else None
    
    # Fetch message list
    messages = service.users().messages().list(userId="me", maxResults=max_results, q=query_label).execute().get("messages", [])
    
    if not messages:
        return []
    
    high_risk_emails = []
    
    # Process emails sequentially
    for msg in messages:
        result = process_email_message(access_token, msg)
    
    # Sort by final_score (highest risk first)
    high_risk_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
    
    return high_risk_emails

@router.get("/fetch-emails-stream")
def fetch_emails_stream(max_results: int = 10, token: str = None, folder: str = "INBOX"):
    """Stream emails to frontend with concurrent Groq AI analysis (parallel processing).
    Accepts token from query param (for frontend persistence) or falls back to session tokens.
    
    Args:
        max_results: Number of emails to fetch (default 10)
        token: Gmail access token
        folder: Email folder/label - "INBOX", "SPAM", "SENT", "DRAFT" (default "INBOX")
    """
    # Use provided token or fall back to in-memory token
    access_token = token or user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Build query to fetch from specific folder/label
    query_label = f"label:{folder}" if folder else None
    
    # Fetch message list
    fetch_list_start = time.time()
    messages = service.users().messages().list(userId="me", maxResults=max_results, q=query_label).execute().get("messages", [])
    fetch_list_time_ms = (time.time() - fetch_list_start) * 1000
    
    def generate():
        """Generator function to stream emails with parallel Groq analysis."""
        total_fetch_time_ms = fetch_list_time_ms
        total_model_time_ms = 0
        total_groq_time_ms = 0
        all_emails = []
        
        # Send initial metadata with total emails expected
        yield f"data: {json.dumps({'type': 'init', 'list_fetch_time_ms': fetch_list_time_ms, 'total_to_fetch': len(messages)})}\n\n"
        
        # Process emails in parallel using ThreadPoolExecutor (max 2 concurrent for stability)
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit all email processing tasks - pass access_token instead of shared service
            future_to_msg = {executor.submit(process_email_message, access_token, msg): msg for msg in messages}
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_msg):
                result = future.result()
                if result:
                    all_emails.append(result)
                    total_fetch_time_ms += result.get("fetch_time_ms", 0)
                    total_model_time_ms += result.get("model_time_ms", 0)
                    total_groq_time_ms += result.get("groq_time_ms", 0)
                    
                    # Stream this email to frontend immediately
                    yield f"data: {json.dumps({'type': 'email', 'email': result, 'count': len(all_emails)})}\n\n"
        
        # Sort by final_score before sending final summary
        all_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
        
        # Send final summary
        yield f"data: {json.dumps({'type': 'complete', 'total_emails': len(all_emails), 'fetch_time_ms': round(total_fetch_time_ms, 2), 'total_model_time_ms': round(total_model_time_ms, 2), 'total_groq_time_ms': round(total_groq_time_ms, 2)})}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")
