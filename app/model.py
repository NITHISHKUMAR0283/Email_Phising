
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Use the recommended public model for phishing detection
MODEL_ID = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"

def load_model(model_name=MODEL_ID):
    """
    Load Hugging Face model and tokenizer for phishing detection.
    Returns model and tokenizer objects.
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    return model, tokenizer

def predict_phishing(model, tokenizer, email_text: str, subject: str = None, sender: str = None) -> dict:
    """
    Predict phishing and suspicious URL probabilities for email_text.
    Optionally logs the score with subject/sender if provided.
    Returns dict with class probabilities.
    """
        # Tokenize input, truncate to model's max length (64 tokens)
    inputs = tokenizer(
            email_text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=64
        )
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()
    # Log to file if subject or sender is provided
    # Optionally print for debugging, but do not log to file in production
    # if subject is not None or sender is not None:
    #     log_str = (
    #         f"[AI SCORE] Subject: {subject or ''}\n"
    #         f"Sender: {sender or ''}\n"
    #         f"Legitimate: {probs[0]:.4f}\n"
    #         f"Phishing: {probs[1]:.4f}\n"
    #         f"Suspicious URL: {probs[2] if len(probs) > 2 else 0.0:.4f}\n\n"
    #     )
    #     print(log_str)
    return {
        "legitimate": probs[0],
        "phishing": probs[1],
        "suspicious_url": probs[2] if len(probs) > 2 else 0.0
    }
