"""
Privacy log, chatbot, and report generation service.
"""

import json
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Any
from .schemas import (
    PrivacyLogEntry, PrivacyEventType, ChatMessage, ChatRequest, ChatResponse,
    FlaggedEmailReport, FlaggedReportData, PrivacyLogResponse
)
from .grok_analysis import call_grok_api
import uuid

# In-memory privacy log (in production, would be a database)
privacy_log: List[PrivacyLogEntry] = []


def append_privacy_log(
    event: PrivacyEventType,
    action: str,
    userId: str = "anonymous",
    emailId: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> PrivacyLogResponse:
    """
    Append entry to privacy log.
    
    Args:
        event: Type of privacy event (chat, report, etc.)
        action: Human-readable description
        userId: User or session ID
        emailId: Associated email ID if applicable
        details: Additional context as dict
    
    Returns:
        PrivacyLogResponse with success and entry ID
    """
    entry = PrivacyLogEntry(
        event=event,
        userId=userId,
        action=action,
        emailId=emailId,
        details=details
    )
    privacy_log.append(entry)
    entry_id = f"{event.value}_{uuid.uuid4().hex[:8]}"
    
    return PrivacyLogResponse(
        success=True,
        message=f"Privacy event logged: {action}",
        entryId=entry_id
    )


def get_privacy_log() -> List[PrivacyLogEntry]:
    """Retrieve full privacy log."""
    return privacy_log


def clear_privacy_log() -> None:
    """Clear privacy log (for testing/reset)."""
    global privacy_log
    privacy_log = []


async def generate_chatbot_response(
    request: ChatRequest
) -> ChatResponse:
    """
    Generate chatbot response using Groq LLM.
    
    Args:
        request: ChatRequest with query and conversation history
    
    Returns:
        ChatResponse with bot message and updated history
    """
    query = request.query
    email_context = ""
    
    # Build comprehensive email context from available data
    if request.context:
        # Email details (handle both camelCase and snake_case)
        sender = request.context.get("sender") or request.context.get("sender")
        subject = request.context.get("subject") or request.context.get("subject")
        risk_score = request.context.get("risk_score") or request.context.get("riskScore") or request.context.get("final_score")
        phishing_risk = request.context.get("phishing_risk") or request.context.get("riskLevel")
        
        if sender:
            email_context += f"📧 Sender: {sender}\n"
        if subject:
            email_context += f"📌 Subject: {subject}\n"
        if risk_score:
            email_context += f"⚠️  Risk Score: {risk_score}\n"
        if phishing_risk:
            email_context += f"🚨 Risk Level: {phishing_risk}\n"
        
        # Analysis or suspicious phrases
        analysis = request.context.get("analysis") or request.context.get("aiAnalysis")
        suspicious_phrases = request.context.get("suspiciousPhrases") or request.context.get("suspicious_phrases")
        red_flags = request.context.get("redFlags") or request.context.get("red_flags")
        
        if analysis:
            if isinstance(analysis, dict):
                email_context += f"\n📊 Analysis:\n"
                if "explanation" in analysis:
                    email_context += f"  {analysis['explanation']}\n"
        
        if suspicious_phrases:
            if isinstance(suspicious_phrases, list) and suspicious_phrases:
                email_context += "\n🔴 Suspicious Phrases Detected:\n"
                for phrase in suspicious_phrases[:5]:  # Limit to 5
                    email_context += f"  • {phrase}\n"
        
        if red_flags:
            if isinstance(red_flags, list) and red_flags:
                email_context += "\n🚩 Red Flags:\n"
                for flag in red_flags[:5]:  # Limit to 5
                    email_context += f"  • {flag}\n"
        
        # Reasons/indicators (from backend analysis)
        reasons = request.context.get("reasons") or request.context.get("indicators")
        if reasons:
            if isinstance(reasons, list) and reasons:
                email_context += "\n🔍 Detected Indicators:\n"
                for reason in reasons:
                    if isinstance(reason, dict):
                        indicator = reason.get("indicator") or reason.get("name")
                        risk_level = reason.get("risk_level")
                        value = reason.get("value")
                        if indicator:
                            email_context += f"  • {indicator}"
                            if risk_level:
                                email_context += f" ({risk_level})"
                            if value:
                                email_context += f": {value}"
                            email_context += "\n"
        
        # URLs
        urls = request.context.get("urls") or request.context.get("suspiciousUrls")
        if urls:
            if isinstance(urls, list) and urls:
                email_context += "\n🔗 Detected URLs:\n"
                for url in urls[:5]:  # Limit to 5
                    email_context += f"  • {url}\n"
        
        # Stats
        if "inboxStats" in request.context:
            stats = request.context["inboxStats"]
            email_context += f"\n📈 Inbox Stats: {json.dumps(stats)}\n"
    
    # Build system prompt with email context
    system_prompt = """You are PhishGPT, an expert email security analyst. 
You have been given detailed analysis of an email. Use this analysis to provide expert insights.

IMPORTANT: 
- Reference the specific email details provided below
- Explain why this email may or may not be phishing
- Provide actionable recommendations based on the analysis
- Be professional, concise, and specific
- If the user asks about the email, use the data already provided - do NOT ask them to share data"""
    
    if email_context:
        system_prompt += f"\n\n=== EMAIL ANALYSIS DATA ===\n{email_context}\n=== END ANALYSIS ===\n"
    
    try:
        # Build full prompt for Groq API
        full_prompt = f"{system_prompt}\n\nUser Question: {query}"
        
        # Call Groq API using run_in_executor to keep async context
        loop = asyncio.get_event_loop()
        bot_response = await loop.run_in_executor(
            None,
            lambda: call_grok_api(full_prompt, json_mode=False)
        )
        
        if not bot_response:
            bot_response = "I encountered an issue processing your request. Please try again."
        
        # Build message history
        user_msg = ChatMessage(role="user", content=query, timestamp=datetime.utcnow())
        assistant_msg = ChatMessage(
            role="assistant",
            content=bot_response,
            timestamp=datetime.utcnow()
        )
        
        updated_history = request.conversationHistory + [user_msg, assistant_msg]
        
        return ChatResponse(
            message=bot_response,
            conversationHistory=updated_history
        )
    
    except Exception as e:
        error_msg = f"Error generating response: {str(e)}"
        user_msg = ChatMessage(role="user", content=query)
        error_response = ChatMessage(role="assistant", content=error_msg)
        
        return ChatResponse(
            message=error_msg,
            conversationHistory=request.conversationHistory + [user_msg, error_response]
        )


def generate_flagged_report(
    flaggedEmails: List[Dict[str, Any]]
) -> FlaggedReportData:
    """
    Generate flagged email report with top 5 high-risk.
    
    Args:
        flaggedEmails: List of flagged email dicts with id, subject, sender, scores, etc.
    
    Returns:
        FlaggedReportData with summary and full list
    """
    # Sort by final_score descending and take top 5
    sorted_flagged = sorted(
        flaggedEmails,
        key=lambda x: x.get("final_score", 0),
        reverse=True
    )
    top_5 = sorted_flagged[:5]
    
    # Convert to report format
    top_risk_reports = [
        FlaggedEmailReport(
            id=email.get("id", "unknown"),
            subject=email.get("subject", ""),
            sender=email.get("sender", ""),
            riskScore=float(email.get("risk_score", 0)),
            finalScore=float(email.get("final_score", 0)),
            reason=email.get("reason", "High phishing indicators detected"),
            tags=email.get("tags", []),
            timestamp=email.get("timestamp", datetime.utcnow().isoformat())
        )
        for email in top_5
    ]
    
    all_reports = [
        FlaggedEmailReport(
            id=email.get("id", "unknown"),
            subject=email.get("subject", ""),
            sender=email.get("sender", ""),
            riskScore=float(email.get("risk_score", 0)),
            finalScore=float(email.get("final_score", 0)),
            reason=email.get("reason", "High phishing indicators detected"),
            tags=email.get("tags", []),
            timestamp=email.get("timestamp", datetime.utcnow().isoformat())
        )
        for email in sorted_flagged
    ]
    
    return FlaggedReportData(
        totalFlagged=len(flaggedEmails),
        topRisks=top_risk_reports,
        allFlagged=all_reports
    )


def export_report_to_csv(report: FlaggedReportData) -> str:
    """
    Convert report to CSV format.
    
    Args:
        report: FlaggedReportData
    
    Returns:
        CSV string with headers and rows
    """
    csv_lines = []
    
    # Header
    csv_lines.append("ID,Subject,Sender,Risk Score,Final Score,Reason,Tags,Timestamp")
    
    # Rows - only allFlagged for complete export
    for email in report.allFlagged:
        tags_str = ";".join(email.tags) if email.tags else ""
        # Escape quotes in subject/sender
        subject = email.subject.replace('"', '""')
        sender = email.sender.replace('"', '""')
        reason = email.reason.replace('"', '""')
        
        csv_lines.append(
            f'{email.id},"{subject}","{sender}",'
            f'{email.riskScore},{email.finalScore},'
            f'"{reason}","{tags_str}",{email.timestamp}'
        )
    
    return "\n".join(csv_lines)
