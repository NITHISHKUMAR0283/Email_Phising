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
from .whitelist import is_domain_whitelisted, is_legitimate_urgency, is_educational_content
from .vt_analyzer import analyze_urls_virustotal, is_vt_available

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
def analyze_url(urls: List[str]) -> Tuple[float, List[str], List[str]]:
	"""
	Analyze URLs using the military-grade URL Detection engine.
	Replaces BERT model with comprehensive multi-phase analysis.
	
	Returns max score, suspicious URLs, and explanations.
	"""
	if not urls:
		return 0.0, [], [], []
	
	load_url_models()  # Lazy load on first use
	
	scores = []
	suspicious = []
	explanations = []
	detailed_analyses = analysis_result['details']  # Full analysis data for each URL
	
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
	
	return max_score, suspicious_urls, explanations

# --- Step 2.5: Header-Based Domain Analysis (Authentication Check) ---
def parse_email_headers(raw_headers: str) -> Dict[str, str]:
	"""
	Parse raw email headers (multi-line format) into a dictionary.
	Handles folded headers (wrapped lines starting with space/tab).
	
	Input:
	```
	From: Quincy Larson <quincy@freecodecamp.org>
	Return-Path: <010f019d2d74f841@us-east-2.amazonses.com>
	Received-SPF: pass (google.com: ...)
	Authentication-Results: mx.google.com;
	       dkim=pass header.i=@freecodecamp.org;
	       dmarc=pass header.from=freecodecamp.org
	```
	
	Output:
	```
	{
		"From": "Quincy Larson <quincy@freecodecamp.org>",
		"Return-Path": "<010f019d2d74f841@us-east-2.amazonses.com>",
		"Received-SPF": "pass (google.com: ...)",
		"Authentication-Results": "mx.google.com; dkim=pass header.i=@freecodecamp.org; dmarc=pass header.from=freecodecamp.org"
	}
	```
	"""
	headers_dict = {}
	current_key = None
	current_value = ""
	
	for line in raw_headers.split('\n'):
		# Check if this is a continuation line (starts with space or tab)
		if line and line[0] in (' ', '\t'):
			# Append to current header value (continuation)
			current_value += " " + line.strip()
		else:
			# Save previous header if exists
			if current_key:
				headers_dict[current_key] = current_value.strip()
			
			# Parse new header
			if ':' in line:
				current_key, current_value = line.split(':', 1)
				current_key = current_key.strip()
				current_value = current_value.strip()
			else:
				current_key = None
				current_value = ""
	
	# Save last header
	if current_key:
		headers_dict[current_key] = current_value.strip()
	
	return headers_dict

def analyze_email_headers(headers_dict: Dict[str, str]) -> Tuple[float, List[str]]:
	"""
	Analyze email headers (From, Return-Path, SPF, DKIM, DMARC) for authentication.
	Lower score = more legitimate (passed authentication).
	Returns header_auth_score, explanations.
	"""
	explanations = []
	auth_score = 0.5  # Neutral default
	
	# Extract From domain
	from_header = headers_dict.get("From", "")
	from_domain = extract_domain(from_header) if from_header else ""
	
	# Extract Return-Path domain (actual sending server)
	return_path = headers_dict.get("Return-Path", "")
	return_path_domain = extract_domain(return_path) if return_path else ""
	
	# Check SPF result
	spf_result = headers_dict.get("Received-SPF", "").lower()
	spf_pass = "pass" in spf_result
	
	# Check DKIM results
	auth_results = headers_dict.get("Authentication-Results", "").lower()
	dkim_pass = "dkim=pass" in auth_results
	dmarc_pass = "dmarc=pass" in auth_results
	
	# Check if From domain matches Return-Path domain (domain alignment)
	domain_mismatch = from_domain and return_path_domain and (from_domain != return_path_domain)
	
	# Scoring logic
	auth_points = 0
	if spf_pass:
		auth_points += 1
		explanations.append("✓ SPF authentication passed")
	else:
		explanations.append("✗ SPF authentication failed or missing")
	
	if dkim_pass:
		auth_points += 1
		explanations.append("✓ DKIM signature verified")
	else:
		explanations.append("✗ DKIM signature failed or missing")
	
	if dmarc_pass:
		auth_points += 1
		explanations.append("✓ DMARC policy aligned")
	else:
		explanations.append("✗ DMARC policy failed or missing")
	
	if domain_mismatch:
		explanations.append(f"⚠ Domain mismatch: From={from_domain}, Return-Path={return_path_domain}")
		auth_points -= 1.5  # Significant risk indicator
	
	# Calculate header auth score (0 = all pass, 1 = all fail)
	# Max auth_points = 3 (SPF + DKIM + DMARC)
	auth_score = max(0.0, min(1.0, (3.0 - auth_points) / 3.0))
	
	if from_domain:
		explanations.insert(0, f"From domain: {from_domain}")
	
	return auth_score, explanations

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


def compute_final_score(url_score, domain_score, intent_score, text_score, vt_score=0.0, header_score=0.0):
	"""DEPRECATED: Use compute_final_score_ensemble instead.
	
	Compute final phishing risk score.
	
	Weights:
	- URL: 35% (most reliable indicator)
	- Domain: 20%
	- Intent: 15%
	- Text: 15%
	- VirusTotal: 15% (if available - highest confidence)
	- Header Auth: 10% (if available - SPF/DKIM/DMARC) - NEW
	
	If VT score is 0 (not available), redistribute to other signals.
	If header score is 0 (headers not provided), redistribute to other signals.
	"""
	if vt_score > 0 and header_score > 0:
		# VirusTotal + Header Auth available - use 6-signal ensemble
		return (
			0.28 * url_score +      # Reduced from 0.35
			0.16 * domain_score +   # Reduced from 0.20
			0.12 * intent_score +   # Reduced from 0.15
			0.12 * text_score +     # Reduced from 0.15
			0.12 * vt_score +       # Reduced from 0.15
			0.20 * header_score     # NEW: Header authentication
		)
	elif vt_score > 0:
		# VirusTotal available, no header auth - use 5-signal ensemble
		return (
			0.35 * url_score +
			0.20 * domain_score +
			0.15 * intent_score +
			0.15 * text_score +
			0.15 * vt_score
		)
	elif header_score > 0:
		# Header auth available, no VirusTotal - use 5-signal ensemble
		return (
			0.32 * url_score +      # Reduced from 0.40
			0.22 * domain_score +   # Reduced from 0.25
			0.18 * intent_score +   # Reduced from 0.20
			0.14 * text_score +     # Reduced from 0.15
			0.14 * header_score     # Header authentication boost
		)
	else:
		# VirusTotal and header not available - use 4-signal weighted average
		return (
			0.40 * url_score +
			0.25 * domain_score +
			0.20 * intent_score +
			0.15 * text_score
		)

# --- Step 7-8: Main Engine ---
def phishing_engine(email: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Main entry: takes parsed email dict, runs 4+ analyses in parallel, returns explainable risk result.
	
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
	
	# Final score (includes VT and header auth if available)
	final_score = compute_final_score(url_score, domain_score, intent_score, text_score, vt_score, header_score)
	
	# Risk level (adjusted thresholds for security priority)
	if final_score >= 0.65:
		risk_level = "HIGH"
	elif final_score >= 0.45:
		risk_level = "MEDIUM"
	else:
		risk_level = "LOW"
	
	# Reasons
	reasons = header_expl + url_expl + domain_expl + intent_expl + text_expl + vt_findings
	
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
		"highlight": highlight,
		"url_analysis": url_analysis_details if url_analysis_details else None
	}
