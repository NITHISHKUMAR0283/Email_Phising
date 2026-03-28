from db.logging import log_email_analysis
from quiz.quiz_engine import get_quiz_question, check_answer
from rag.knowledge_retrieval import retrieve_similar_cases
from llm.reasoning import generate_reasoning
"""
PhishGuard AI Backend Entry Point
FastAPI app for phishing detection, explanation, quizzes, and logging.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from detection.ensemble import ensemble_detect
from explain.token_highlighter import highlight_tokens
from explain.explanation import generate_explanation


app = FastAPI(title="PhishGuard AI Backend")

# CORS for local frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"message": "PhishGuard AI Backend is running."}


# --- Detection API ---
# --- Detection API ---
class EmailDetectionRequest(BaseModel):
    email_text: str
    url: str | None = None
    headers: dict | None = None

@app.post("/detect")
def detect_email(req: EmailDetectionRequest):
    result = ensemble_detect(req.email_text, req.url, req.headers)
    log_email_analysis({
        "email_text": req.email_text,
        "url": req.url,
        "headers": req.headers,
        "result": result
    })
    return result


# --- Explainable AI API ---
# --- Explainable AI API ---
class ExplainRequest(BaseModel):
    email_text: str
# --- LLM Reasoning API ---
# --- LLM Reasoning API ---
class ReasoningRequest(BaseModel):
    email_text: str
    url: str | None = None
    headers: dict | None = None
# --- RAG Knowledge Retrieval API ---
class RAGRequest(BaseModel):
    email_text: str
# --- Quiz API ---
class QuizRequest(BaseModel):
    user_history: list | None = None

@app.post("/quiz")
def quiz_question(req: QuizRequest):
    q = get_quiz_question(req.user_history or [])
    return q

class QuizAnswerRequest(BaseModel):
    question_id: int
    user_answer: bool

@app.post("/quiz/answer")
def quiz_answer(req: QuizAnswerRequest):
    result = check_answer(req.question_id, req.user_answer)
    return result

@app.post("/rag")
def rag_retrieve(req: RAGRequest):
    cases = retrieve_similar_cases(req.email_text)
    return {"similar_cases": cases}

@app.post("/reasoning")
def llm_reasoning(req: ReasoningRequest):
    reasoning = generate_reasoning(req.email_text, req.url, req.headers)
    return {"reasoning": reasoning}

@app.post("/explain")
def explain_email(req: ExplainRequest):
    tokens = highlight_tokens(req.email_text)
    explanation = generate_explanation(req.email_text, tokens)
    return {
        "highlighted_tokens": tokens,
        "explanation": explanation
    }
