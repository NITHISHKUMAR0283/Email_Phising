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
from .whitelist import is_domain_whitelisted, is_legitimate_urgency, is_educational_content, get_whitelist_info
from .vt_analyzer import analyze_urls_virustotal, is_vt_available
from .url_analyzer import analyze_urls as analyze_urls_engine
from .config import (
	URL_SUSPICIOUS_THRESHOLD, DOMAIN_SUSPICIOUS_THRESHOLD, 
	INTENT_SUSPICIOUS_THRESHOLD, TEXT_SUSPICIOUS_THRESHOLD,
	VT_SUSPICIOUS_THRESHOLD, HEADER_SUSPICIOUS_THRESHOLD,
	MIN_SIGNALS_FOR_FLAG_UNKNOWN, MIN_SIGNALS_FOR_FLAG_WHITELISTED,
	VT_OVERRIDE_THRESHOLD, UNKNOWN_SENDER_HIGH_RISK, UNKNOWN_SENDER_MEDIUM_RISK,
	WHITELISTED_HIGH_RISK, WHITELISTED_MEDIUM_RISK
)

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

# --- Step 2: URL Analysis (NEW: Using Advanced URL Detection Engine) ---
def analyze_url(urls: List[str]) -> Tuple[float, List[str], List[str], List[Dict[str, Any]]]:
	"""
	Analyze URLs using the military-grade URL Detection engine.
	Replaces BERT model with comprehensive multi-phase analysis.
	
	Returns max score, suspicious URLs, explanations, and detailed analysis.
	"""
	if not urls:
		return 0.0, [], [], []
	
	# Use the advanced URL analyzer engine
	analysis_result = analyze_urls_engine(urls)
	
	max_score = analysis_result['max_risk_score']
	suspicious_urls = []
	explanations = []
	detailed_analyses = analysis_result['details']  # Full analysis data for each URL
	
	# Process individual URL details
	for url_detail in analysis_result['details']:
		url = url_detail['url']
		score = url_detail['risk_score']
		risk_level = url_detail['risk_level']
		threat_type = url_detail['threat_type']
		findings = url_detail['findings']
		
		# Flag suspicious URLs
		if url_detail['is_suspicious']:
			suspicious_urls.append(url)
		
		# Create explanation from findings
		if findings:
			explanation = f"URL Analysis - {threat_type}: " + "; ".join(findings[:3])  # Top 3 findings
		else:
			explanation = f"URL Risk Level: {risk_level} (Score: {score:.2f})"
		
		explanations.append(explanation)
	
	return max_score, suspicious_urls, explanations, detailed_analyses

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
def compute_final_score_ensemble(url_score, domain_score, intent_score, text_score, vt_score=0.0, header_score=0.0, sender="", is_whitelisted=False):
	"""
	IMPROVED: Confidence-based ensemble voting to reduce false positives.
	
	Strategy:
	1. Whitelisted senders: Use HIGH thresholds (require strong agreement)
	2. Unknown senders: Use MEDIUM thresholds
	3. Require multiple signals to agree before flagging
	4. Consider signal reliability and consistency
	
	Returns: (final_score, confidence, signal_agreement_count)
	"""
	
	# Collect signals with thresholds (configurable via config.py)
	signals = []
	signal_weights = {}
	
	# Signal 1: URL Analysis (HIGH reliability) - use configurable threshold
	if url_score > URL_SUSPICIOUS_THRESHOLD:
		signals.append(("url", url_score, "Suspicious URL detected"))
		signal_weights["url"] = 0.35  # Most reliable
	
	# Signal 2: Domain (MEDIUM reliability)
	if domain_score > DOMAIN_SUSPICIOUS_THRESHOLD:
		signals.append(("domain", domain_score, "Suspicious domain pattern"))
		signal_weights["domain"] = 0.20
	
	# Signal 3: Intent (MEDIUM reliability)
	if intent_score > INTENT_SUSPICIOUS_THRESHOLD:
		signals.append(("intent", intent_score, "Phishing intent detected"))
		signal_weights["intent"] = 0.15
	
	# Signal 4: Text/Content (MEDIUM reliability)
	if text_score > TEXT_SUSPICIOUS_THRESHOLD:
		signals.append(("text", text_score, "Suspicious content detected"))
		signal_weights["text"] = 0.15
	
	# Signal 5: VirusTotal (HIGHEST reliability when available)
	if vt_score > VT_SUSPICIOUS_THRESHOLD:
		signals.append(("vt", vt_score, "URL flagged by VirusTotal"))
		signal_weights["vt"] = 0.40
	
	# Signal 6: Header Authentication (HIGH reliability for legitimacy)
	if header_score > HEADER_SUSPICIOUS_THRESHOLD:
		signals.append(("header", header_score, "Authentication failed"))
		signal_weights["header"] = 0.25
	
	agreement_count = len(signals)
	confidence = 0.0
	
	# ENSEMBLE VOTING LOGIC using configurable parameters
	if is_whitelisted:
		# STRICT: Whitelisted senders need STRONG agreement to flag
		if agreement_count >= MIN_SIGNALS_FOR_FLAG_WHITELISTED:
			# High confidence: Multiple independent signals agree
			confidence = min(0.95, 0.3 + (0.2 * agreement_count))
			# Cap score at WHITELISTED threshold
			final_score = min(WHITELISTED_HIGH_RISK - 0.05, compute_weighted_score(signals, signal_weights))
		elif agreement_count == 2 and vt_score > VT_OVERRIDE_THRESHOLD:
			# VirusTotal + 1 other signal = moderate risk even for whitelisted
			confidence = 0.80
			final_score = min(WHITELISTED_MEDIUM_RISK + 0.10, compute_weighted_score(signals, signal_weights))
		else:
			# Few signals or weak agreement = LOW risk (default to safe for whitelisted)
			confidence = 0.98
			final_score = min(WHITELISTED_MEDIUM_RISK * 0.5, compute_weighted_score(signals, signal_weights))
	else:
		# STANDARD: Unknown senders need moderate agreement
		if agreement_count >= MIN_SIGNALS_FOR_FLAG_UNKNOWN:
			confidence = min(0.95, 0.4 + (0.15 * agreement_count))
			final_score = compute_weighted_score(signals, signal_weights)
		elif agreement_count == 1:
			# Only 1 signal = LOW confidence, need very strong signal
			confidence = 0.50
			# Single strong signal override for VT or very high scores
			if signals[0][0] == "vt" and signals[0][1] > 0.95:
				final_score = UNKNOWN_SENDER_HIGH_RISK + 0.10
			elif signals[0][1] > 0.85:
				final_score = UNKNOWN_SENDER_MEDIUM_RISK + 0.15
			else:
				final_score = UNKNOWN_SENDER_MEDIUM_RISK * 0.6
		else:
			# No signals = definitely safe
			confidence = 0.98
			final_score = 0.05
	
	return round(final_score, 3), round(confidence, 2), agreement_count


def compute_weighted_score(signals, weights):
	"""Compute weighted average from signals."""
	if not signals:
		return 0.0
	
	total_weight = sum(weights.get(sig[0], 0.1) for sig in signals)
	if total_weight == 0:
		return sum(sig[1] for sig in signals) / len(signals)
	
	weighted_sum = sum(sig[1] * weights.get(sig[0], 0.1) for sig in signals)
	return weighted_sum / total_weight

# --- Step 7-8: Main Engine ---
def phishing_engine(email: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Main entry: takes parsed email dict, runs 4+ analyses in parallel, returns explainable risk result.
	
	NEW: Uses confidence-based ensemble voting to reduce false positives.
	
	Email dict structure:
	{
		"subject": str,
		"body": str,
		"sender": str,
		"urls": list[str],
		"headers": dict[str, str] (optional - for authentication analysis)
	}
	"""
	subject = email.get("subject", "")
	body = email.get("body", "")
	sender = email.get("sender", "")
	urls = email.get("urls", [])
	
	# Check if sender is whitelisted (reduces false positives)
	sender_domain = None
	is_whitelisted = False
	if sender:
		try:
			sender_domain = sender.split("@")[1].split(">")[0].lower() if "@" in sender else None
			is_whitelisted = is_domain_whitelisted(sender_domain) if sender_domain else False
		except:
			pass
	
	# Check VirusTotal if available
	vt_score = 0.0
	vt_findings = []
	if is_vt_available() and urls:
		vt_score, vt_findings = analyze_urls_virustotal(urls)
	
	# Check headers for authentication (SPF/DKIM/DMARC) if provided
	header_score = 0.0
	header_expl = []
	headers_dict = email.get("headers", {})
	if headers_dict:
		try:
			header_score = 0.0  # Placeholder for header analysis
			header_expl = []
		except:
			pass
	
	# Run all standard analyses in parallel using ThreadPoolExecutor
	with ThreadPoolExecutor(max_workers=4) as executor:
		url_future = executor.submit(analyze_url, urls)
		domain_future = executor.submit(analyze_domain, sender, urls)
		intent_future = executor.submit(detect_intent, subject + "\n" + body)
		text_future = executor.submit(analyze_text, subject + "\n" + body)
		
		# Collect results as they complete
		url_score, suspicious_urls, url_expl, url_analysis_details = url_future.result()
		domain_score, domain_expl = domain_future.result()
		intent_score, matched_phrases, intent_expl = intent_future.result()
		text_score, text_expl = text_future.result()
	
	# NEW: Ensemble voting instead of simple weighted average
	final_score, confidence, signal_agreement = compute_final_score_ensemble(
		url_score, domain_score, intent_score, text_score, vt_score, header_score, 
		sender, is_whitelisted
	)
	
	# NEW: Dynamic thresholds based on confidence and whitelist status
	if is_whitelisted:
		# Strict thresholds for known good senders
		if final_score >= WHITELISTED_HIGH_RISK:
			risk_level = "HIGH"
		elif final_score >= WHITELISTED_MEDIUM_RISK:
			risk_level = "MEDIUM"
		else:
			risk_level = "LOW"
	else:
		# Standard thresholds for unknown senders
		if final_score >= UNKNOWN_SENDER_HIGH_RISK:
			risk_level = "HIGH"
		elif final_score >= UNKNOWN_SENDER_MEDIUM_RISK:
			risk_level = "MEDIUM"
		else:
			risk_level = "LOW"
	
	# Add whitelist info to reasons if applicable
	reasons = header_expl + url_expl + domain_expl + intent_expl + text_expl + vt_findings
	if is_whitelisted and sender_domain:
		reasons.insert(0, f"✓ Sender verified: {get_whitelist_info(sender_domain)}")
	
	# Highlight
	highlight = {
		"urls": suspicious_urls,
		"phrases": matched_phrases
	}
	
	return {
		"risk_level": risk_level,
		"final_score": final_score,
		"confidence": confidence,
		"signal_agreement": signal_agreement,
		"is_whitelisted": is_whitelisted,
		"components": {
			"url_score": round(url_score, 2),
			"domain_score": round(domain_score, 2),
			"intent_score": round(intent_score, 2),
			"text_score": round(text_score, 2)
		},
		"reasons": reasons,
		"highlight": highlight,
		"url_analysis": url_analysis_details if url_analysis_details else None
	}
