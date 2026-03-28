"""
RAG Knowledge Retrieval Module (ChromaDB placeholder)
"""
from typing import List

def retrieve_similar_cases(email_text: str) -> List[str]:
    """
    Retrieve similar phishing cases from offline threat database (ChromaDB).
    """
    # TODO: Integrate with ChromaDB/FAISS for real retrieval
    if "urgent" in email_text.lower():
        return ["Enron phishing 2002", "CEAS 2015 phishing"]
    return ["No similar cases found"]
