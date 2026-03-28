"""
Adaptive Awareness Quiz Engine
"""
from typing import List, Dict

QUIZ_QUESTIONS = [
    {
        "id": 1,
        "email_text": "Urgent! Click this link to reset your password.",
        "is_phishing": True,
        "explanation": "Creates urgency and contains suspicious link."
    },
    {
        "id": 2,
        "email_text": "Your invoice is attached. Please review.",
        "is_phishing": False,
        "explanation": "No suspicious patterns detected."
    }
]

def get_quiz_question(user_history: List[Dict] = None) -> Dict:
    """
    Returns a quiz question, optionally adapting to user history.
    """
    # TODO: Make adaptive based on user_history
    if user_history and any(q['mistake'] for q in user_history):
        return QUIZ_QUESTIONS[0]
    return QUIZ_QUESTIONS[1]

def check_answer(question_id: int, user_answer: bool) -> Dict:
    """
    Checks user's answer and returns result and explanation.
    """
    q = next((q for q in QUIZ_QUESTIONS if q["id"] == question_id), None)
    if not q:
        return {"correct": False, "explanation": "Invalid question."}
    correct = (q["is_phishing"] == user_answer)
    return {"correct": correct, "explanation": q["explanation"]}
