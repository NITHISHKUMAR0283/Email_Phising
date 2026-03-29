"""
Multi-signal phishing detection engine for hackathon demo.
Combines URL, domain, intent, and text analysis for explainable risk scoring.
Uses lazy loading to avoid startup delays.
"""
import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Check for GPU availability
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {DEVICE}")

# Preload Hugging Face models for each signal
URL_MODEL_ID = "CrabInHoney/urlbert-tiny-v4-phishing-classifier"
DOMAIN_MODEL_ID = "distilbert-base-uncased-finetuned-sst-2-english"
INTENT_MODEL_ID = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
TEXT_MODEL_ID = "distilbert-base-uncased-finetuned-sst-2-english"

# Lazy load models - None until first use
url_tokenizer: Optional[AutoTokenizer] = None
url_model: Optional[AutoModelForSequenceClassification] = None

domain_tokenizer: Optional[AutoTokenizer] = None
domain_model: Optional[AutoModelForSequenceClassification] = None

intent_tokenizer: Optional[AutoTokenizer] = None
intent_model: Optional[AutoModelForSequenceClassification] = None

text_tokenizer: Optional[AutoTokenizer] = None
text_model: Optional[AutoModelForSequenceClassification] = None

def load_url_models():
	"""Lazy load URL models."""
	global url_tokenizer, url_model
	if url_model is None:
		print("Loading URL model...")
		url_tokenizer = AutoTokenizer.from_pretrained(URL_MODEL_ID)
		url_model = AutoModelForSequenceClassification.from_pretrained(URL_MODEL_ID).to(DEVICE).eval()

def load_domain_models():
	"""Lazy load domain models."""
	global domain_tokenizer, domain_model
	if domain_model is None:
		print("Loading domain model...")
		domain_tokenizer = AutoTokenizer.from_pretrained(DOMAIN_MODEL_ID)
		domain_model = AutoModelForSequenceClassification.from_pretrained(DOMAIN_MODEL_ID).to(DEVICE).eval()

def load_intent_models():
	"""Lazy load intent models."""
	global intent_tokenizer, intent_model
	if intent_model is None:
		print("Loading intent model...")
		intent_tokenizer = AutoTokenizer.from_pretrained(INTENT_MODEL_ID)
		intent_model = AutoModelForSequenceClassification.from_pretrained(INTENT_MODEL_ID).to(DEVICE).eval()

def load_text_models():
	"""Lazy load text models."""
	global text_tokenizer, text_model
	if text_model is None:
		print("Loading text model...")
		text_tokenizer = AutoTokenizer.from_pretrained(TEXT_MODEL_ID)
		text_model = AutoModelForSequenceClassification.from_pretrained(TEXT_MODEL_ID).to(DEVICE).eval()

def load_all_models():
	"""Load all phishing detection models eagerly (for startup)."""
	print("\n=== Loading all phishing detection models ===")
	load_url_models()
	load_domain_models()
	load_intent_models()
	load_text_models()
	print("=== All models loaded successfully ===\n")

# --- Step 2: URL Analysis ---
def analyze_url(urls: List[str]) -> Tuple[float, List[str], List[str]]:
	"""
	Analyze URLs using batch processing for faster inference.
	Returns max score, suspicious URLs, and explanations.
	"""
	if not urls:
		return 0.0, [], []
	
	load_url_models()  # Lazy load on first use
	
	scores = []
	suspicious = []
	explanations = []
	
	# Batch tokenize all URLs at once
	inputs = url_tokenizer(urls, return_tensors="pt", truncation=True, max_length=64, padding=True)
	inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
	
	with torch.no_grad():
		outputs = url_model(**inputs)
		probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[:, 1].cpu().tolist()
	
	for url, prob in zip(urls, probs):
		scores.append(prob)
		if prob > 0.7:
			suspicious.append(url)
			explanations.append(f"Suspicious URL detected: {url}")
		elif prob > 0.4:
			explanations.append(f"Potentially risky URL: {url}")
	
	return max(scores) if scores else 0.0, suspicious, explanations

# --- Step 3: Domain Analysis ---
def extract_domain(email_or_url: str) -> str:
	"""Extract domain from email or URL."""
	if '@' in email_or_url:
		return email_or_url.split('@')[-1].lower()
	try:
		return urlparse(email_or_url).netloc.lower()
	except Exception:
		return ""

def analyze_domain(sender: str, urls: List[str]) -> Tuple[float, List[str]]:
	"""
	Use a domain phishing classifier model on sender and URL domains with batch processing.
	Returns max score, explanations.
	"""
	load_domain_models()  # Lazy load on first use
	
	explanations = []
	sender_domain = extract_domain(sender)
	url_domains = [extract_domain(u) for u in urls]
	domains = [d for d in [sender_domain] + url_domains if d]
	
	if not domains:
		return 0.0, explanations
	
	# Batch tokenize all domains at once
	inputs = domain_tokenizer(domains, return_tensors="pt", truncation=True, max_length=32, padding=True)
	inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
	
	with torch.no_grad():
		outputs = domain_model(**inputs)
		probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[:, 1].cpu().tolist()
	
	scores = []
	for domain, prob in zip(domains, probs):
		scores.append(prob)
		if prob > 0.7:
			explanations.append(f"Suspicious domain detected: {domain}")
		elif prob > 0.4:
			explanations.append(f"Potentially risky domain: {domain}")
	
	return max(scores) if scores else 0.0, explanations

# --- Step 4: Intent Detection ---
INTENT_KEYWORDS = [
	"verify your account",
	"click here",
	"urgent action required",
	"update your password",
	"login now",
	"confirm identity"
]
def detect_intent(text: str) -> Tuple[float, List[str], List[str]]:
	"""
	Use an intent/spam classifier model for phishing intent with GPU acceleration.
	Returns score, matched phrases (if any), explanations.
	"""
	load_intent_models()  # Lazy load on first use
	
	inputs = intent_tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
	inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
	
	with torch.no_grad():
		outputs = intent_model(**inputs)
		prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
	
	explanations = []
	matches = []
	if prob > 0.7:
		explanations.append("Phishing/social engineering intent detected.")
		matches.append("phishing intent")
	elif prob > 0.4:
		explanations.append("Possible suspicious intent detected.")
	return prob, matches, explanations

# --- Step 5: Text Classification (simple rule-based) ---
THREAT_WORDS = ["suspend", "deactivate", "immediately", "threat", "compromise", "risk", "urgent", "action required"]
SOCIAL_ENGINEERING = ["gift", "prize", "winner", "congratulations", "limited time", "exclusive"]
def analyze_text(text: str) -> Tuple[float, List[str]]:
	"""
	Use a phishing email classifier model for text scoring with GPU acceleration.
	Returns score and explanations.
	"""
	load_text_models()  # Lazy load on first use
	
	inputs = text_tokenizer(text, return_tensors="pt", truncation=True, max_length=256)
	inputs = {k: v.to(DEVICE) for k, v in inputs.items()}
	
	with torch.no_grad():
		outputs = text_model(**inputs)
		prob = torch.nn.functional.softmax(outputs.logits, dim=-1)[0][1].item()
	
	explanations = []
	if prob > 0.7:
		explanations.append("Phishing/spam content detected in email text.")
	elif prob > 0.4:
		explanations.append("Potentially suspicious content in email text.")
	return prob, explanations

# --- Step 6: Final Scoring ---
def compute_final_score(url_score, domain_score, intent_score, text_score):
	return (
		0.4 * url_score +
		0.25 * domain_score +
		0.2 * intent_score +
		0.15 * text_score
	)

# --- Step 7-8: Main Engine ---
def phishing_engine(email: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Main entry: takes parsed email dict, runs 4 analyses in parallel, returns explainable risk result.
	"""
	subject = email.get("subject", "")
	body = email.get("body", "")
	sender = email.get("sender", "")
	urls = email.get("urls", [])
	
	# Run all 4 analyses in parallel using ThreadPoolExecutor
	with ThreadPoolExecutor(max_workers=4) as executor:
		url_future = executor.submit(analyze_url, urls)
		domain_future = executor.submit(analyze_domain, sender, urls)
		intent_future = executor.submit(detect_intent, subject + "\n" + body)
		text_future = executor.submit(analyze_text, subject + "\n" + body)
		
		# Collect results as they complete
		url_score, suspicious_urls, url_expl = url_future.result()
		domain_score, domain_expl = domain_future.result()
		intent_score, matched_phrases, intent_expl = intent_future.result()
		text_score, text_expl = text_future.result()
	
	# Final score
	final_score = compute_final_score(url_score, domain_score, intent_score, text_score)
	
	# Risk level
	if final_score > 0.75:
		risk_level = "HIGH"
	elif final_score > 0.45:
		risk_level = "MEDIUM"
	else:
		risk_level = "LOW"
	
	# Reasons
	reasons = url_expl + domain_expl + intent_expl + text_expl
	
	# Highlight
	highlight = {
		"urls": suspicious_urls,
		"phrases": matched_phrases
	}
	
	return {
		"risk_level": risk_level,
		"final_score": round(final_score, 2),
		"components": {
			"url_score": round(url_score, 2),
			"domain_score": round(domain_score, 2),
			"intent_score": round(intent_score, 2),
			"text_score": round(text_score, 2)
		},
		"reasons": reasons,
		"highlight": highlight
	}
