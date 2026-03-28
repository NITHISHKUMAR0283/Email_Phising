import os
import base64
from fastapi import APIRouter, Request, Response
from fastapi import Cookie
from fastapi.responses import RedirectResponse, JSONResponse
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from .model import predict_phishing, load_model
from .heuristics import analyze_heuristics
from .utils import combine_signals, extract_highlighted_tokens
from .quiz import generate_quiz
from typing import Dict, Any

CLIENT_ID = "685356081512-k89ps7iino08oqlc2bipvt73eqar3apo.apps.googleusercontent.com"
CLIENT_SECRET = "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"
REDIRECT_URI = "http://localhost:8000/oauth2callback"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

router = APIRouter()
user_tokens = {}
code_verifiers = {}
model, tokenizer = load_model()

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

@router.get("/fetch-high-risk-emails")
def fetch_high_risk_emails():
    access_token = user_tokens.get("access_token")
    if not access_token:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    creds = Credentials(token=access_token)
    service = build("gmail", "v1", credentials=creds)
    messages = service.users().messages().list(userId="me", maxResults=10).execute().get("messages", [])
    high_risk_emails = []
    for msg in messages:
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
        headers = {h["name"]: h["value"] for h in msg_data["payload"]["headers"]}
        subject = headers.get("Subject", "")
        sender = headers.get("From", "")
        body = ""
        if "parts" in msg_data["payload"]:
            for part in msg_data["payload"]["parts"]:
                if part["mimeType"] == "text/plain":
                    data = part["body"].get("data", "")
                    if data:
                        body = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
        else:
            data = msg_data["payload"]["body"].get("data", "")
            if data:
                body = base64.urlsafe_b64decode(data + '==').decode("utf-8", errors="ignore")
        # Run AI + heuristics
        heuristics = analyze_heuristics(body, sender, None, headers)
        model_probs = predict_phishing(model, tokenizer, body, subject=subject, sender=sender)

        combined_score = min(model_probs["phishing"], 1.0)
        result = combine_signals(model_probs["phishing"], heuristics)
        highlighted = extract_highlighted_tokens(body, heuristics)
        quiz = generate_quiz(body, highlighted)
        risk_score_percent = int(round(combined_score * 100))
        high_risk_emails.append({
            "subject": subject,
            "sender": sender,
            "risk_score": result["risk_score"],  # e.g. 'High'
            "phishing_score": model_probs["phishing"],  # e.g. 0.87
            "phishingPercentage": risk_score_percent,  # e.g. 87
            "highlighted_tokens": highlighted,
            "heuristics": heuristics["signals"],
            "quiz": quiz,
            "body": body,
            "timestamp": msg_data.get("internalDate", "")
        })
    return high_risk_emails
