
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from typing import Optional, Tuple

# Check for GPU availability
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Use the recommended public model for phishing detection
MODEL_ID = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"

# Model cache to avoid reloading
_cached_model = None
_cached_tokenizer = None

def load_model(model_name=MODEL_ID) -> Tuple[AutoModelForSequenceClassification, AutoTokenizer]:
    """
    Load Hugging Face model and tokenizer for phishing detection.
    Uses caching to avoid reloading the same model.
    Returns model and tokenizer objects.
    """
    global _cached_model, _cached_tokenizer
    
    if _cached_model is not None:
        return _cached_model, _cached_tokenizer
    
    print(f"Loading model on {DEVICE}...")
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name).to(DEVICE).eval()
    
    _cached_model = model
    _cached_tokenizer = tokenizer
    
    return model, tokenizer

def predict_phishing(model, tokenizer, email_text: str, subject: str = None, sender: str = None) -> dict:
    """
    Predict phishing and suspicious URL probabilities for email_text with GPU acceleration.
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
    
    # Move to device
    inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
    
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].cpu().tolist()
    
    return {
        "legitimate": probs[0],
        "phishing": probs[1],
        "suspicious_url": probs[2] if len(probs) > 2 else 0.0
    }
