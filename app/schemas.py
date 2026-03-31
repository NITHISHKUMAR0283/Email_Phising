"""
Pydantic schemas for chatbot, reports, and privacy logs.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class PrivacyEventType(str, Enum):
    """Privacy log event types."""
    CHAT_QUERY = "chat_query"
    REPORT_GENERATED = "report_generated"
    EMAIL_VIEWED = "email_viewed"
    API_CALL = "api_call"
    EXPORT_DATA = "export_data"


class PrivacyLogEntry(BaseModel):
    """Privacy audit log entry."""
    event: PrivacyEventType
    userId: Optional[str] = Field(default="anonymous", description="User or session ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str = Field(..., description="Action description")
    emailId: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ChatMessage(BaseModel):
    """Single chat message in conversation."""
    role: str = Field(..., description="'user' or 'assistant'")
    content: str = Field(..., description="Message text")
    timestamp: Optional[datetime] = None


class ChatRequest(BaseModel):
    """Request to chatbot endpoint."""
    query: str = Field(..., description="User query/prompt")
    conversationHistory: List[ChatMessage] = Field(default=[], description="Prior messages")
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Context like selectedEmailId, inboxStats, flaggedEmailCount"
    )


class ChatResponse(BaseModel):
    """Response from chatbot endpoint."""
    message: str = Field(..., description="Bot response text")
    conversationHistory: List[ChatMessage] = Field(..., description="Updated conversation")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class FlaggedEmailReport(BaseModel):
    """Single flagged email in report."""
    id: str
    subject: str
    sender: str
    riskScore: float
    finalScore: float
    reason: str
    tags: List[str]
    timestamp: str


class FlaggedReportData(BaseModel):
    """Flagged emails report."""
    generatedAt: datetime = Field(default_factory=datetime.utcnow)
    totalFlagged: int
    topRisks: List[FlaggedEmailReport] = Field(..., description="Top 5 highest risk")
    allFlagged: List[FlaggedEmailReport]


class PrivacyLogResponse(BaseModel):
    """Response after logging privacy event."""
    success: bool
    message: str
    entryId: Optional[str] = None
