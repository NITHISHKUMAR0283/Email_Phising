
import random
from typing import List, Dict

def generate_quiz(email_text: str, highlighted_tokens: List[str]) -> List[Dict]:
    """
    Generate 1-3 quiz questions based on risky tokens in the email.
    Each question asks the user to identify a phishing phrase.
    Returns a list of quiz question dicts.
    """
    questions = []
    if not highlighted_tokens:
        return questions
    for i, token in enumerate(highlighted_tokens[:3]):
        options = [token, "Hello", "Thank you"]
        random.shuffle(options)
        questions.append({
            "question": f"Which phrase indicates phishing?",
            "options": options,
            "correct": [token]
        })
    return questions
