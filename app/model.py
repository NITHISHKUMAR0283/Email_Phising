"""
Model loading and phishing prediction using DistilBERT
"""
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch


# Use the recommended public model for phishing detection
MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

def load_model(model_name=MODEL_ID):
    """
    Load Hugging Face model and tokenizer for phishing detection.
    """
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    return model, tokenizer

def predict_phishing(model, tokenizer, email_text: str) -> dict:
    """
    Predict phishing and suspicious URL probabilities for email_text.
    Returns dict with class probabilities.
    """
    inputs = tokenizer(email_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()
    # Model classes: [legitimate, phishing, suspicious_url]
    return {
        "legitimate": probs[0],
        "phishing": probs[1],
        "suspicious_url": probs[2] if len(probs) > 2 else 0.0
    }
