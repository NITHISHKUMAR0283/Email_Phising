import os
import base64
import re
import time
import json
from fastapi import APIRouter, Request, Response
from fastapi import Cookie
from fastapi.responses import RedirectResponse, JSONResponse, StreamingResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .phishing_engine import phishing_engine
from typing import Dict, Any, List

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
    response = RedirectResponse("http://localhost:5173/")
    response.delete_cookie("code_verifier")
    return response

@router.get("/check-auth")
def check_auth():
    """Check if user is authenticated by verifying access token exists."""
    access_token = user_tokens.get("access_token")
    if access_token:
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
    """Extract email body from payload."""
    body = ""
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                data = part["body"].get("data", "")
                if data:
                    body = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
                    break
    else:
        data = payload["body"].get("data", "")
        if data:
            body = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
    return body

def process_email_message(service, msg: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Process a single email message.
    Returns result with timing info, or None if parse fails.
    """
    fetch_start = time.time()
    
    try:
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        fetch_time = (time.time() - fetch_start) * 1000
        
        if not msg_data or "payload" not in msg_data:
            return None
        
        headers = {h["name"]: h["value"] for h in msg_data.get("payload", {}).get("headers", [])}
        subject = headers.get("Subject", "")
        sender = headers.get("From", "")
        body = extract_email_body(msg_data.get("payload", {}))
        
        # Extract URLs from body
        urls = re.findall(r'https?://\S+', body) if body else []
        
        # Run phishing_engine with timing
        model_start = time.time()
        email_obj = {
            "subject": subject,
            "body": body,
            "sender": sender,
            "urls": urls
        }
        result = phishing_engine(email_obj)
        model_time = (time.time() - model_start) * 1000
        
        return {
            "id": msg["id"],
            "subject": subject,
            "sender": sender,
            "risk_score": result.get("risk_level"),
            "final_score": result.get("final_score"),
            "components": result.get("components"),
            "reasons": result.get("reasons"),
            "highlight": result.get("highlight"),
            "body": body,
            "timestamp": msg_data.get("internalDate", ""),
            "fetch_time_ms": round(fetch_time, 2),
            "model_time_ms": round(model_time, 2)
        }
            
    except Exception as e:
        error_str = str(e)
        print(f"Error processing email {msg.get('id')}: {error_str[:80]}")
    
    return None

@router.get("/fetch-all-emails")
def fetch_all_emails(max_results: int = 20):
    """Fetch emails with phishing analysis and timing information."""
    total_start = time.time()
    
    access_token = user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Fetch message list
    fetch_list_start = time.time()
    messages = service.users().messages().list(userId="me", maxResults=max_results).execute().get("messages", [])
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
        result = process_email_message(service, msg)
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
def fetch_high_risk_emails():
    access_token = user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Fetch message list
    messages = service.users().messages().list(userId="me", maxResults=20).execute().get("messages", [])
    
    if not messages:
        return []
    
    high_risk_emails = []
    
    # Process emails sequentially
    for msg in messages:
        result = process_email_message(service, msg)
        if result and result.get("risk_score") == "HIGH":
            high_risk_emails.append(result)
    
    # Sort by final_score (highest risk first)
    high_risk_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
    
    return high_risk_emails

@router.get("/fetch-emails-stream")
def fetch_emails_stream(max_results: int = 20):
    """Stream emails one by one to frontend as they are processed."""
    access_token = user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    
    # Fetch message list
    fetch_list_start = time.time()
    messages = service.users().messages().list(userId="me", maxResults=max_results).execute().get("messages", [])
    fetch_list_time_ms = (time.time() - fetch_list_start) * 1000
    
    def generate():
        """Generator function to stream emails one by one."""
        total_fetch_time_ms = fetch_list_time_ms
        total_model_time_ms = 0
        all_emails = []
        
        # Send initial metadata
        yield f"data: {json.dumps({'type': 'init', 'list_fetch_time_ms': fetch_list_time_ms})}\n\n"
        
        # Process and send each email as it's done
        for idx, msg in enumerate(messages):
            result = process_email_message(service, msg)
            if result:
                all_emails.append(result)
                total_fetch_time_ms += result.get("fetch_time_ms", 0)
                total_model_time_ms += result.get("model_time_ms", 0)
                
                # Send this email to frontend
                yield f"data: {json.dumps({'type': 'email', 'email': result, 'count': len(all_emails)})}\n\n"
        
        # Sort by final_score before sending final summary
        all_emails.sort(key=lambda x: float(x.get("final_score", 0)), reverse=True)
        
        # Send final summary
        yield f"data: {json.dumps({'type': 'complete', 'total_emails': len(all_emails), 'fetch_time_ms': round(total_fetch_time_ms, 2), 'total_model_time_ms': round(total_model_time_ms, 2)})}\n\n"
    
    return StreamingResponse(generate(), media_type="text/event-stream")
