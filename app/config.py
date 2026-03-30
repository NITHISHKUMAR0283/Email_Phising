"""
Configuration for phishing detection thresholds and parameters.
Allows easy tuning to reduce false positives/negatives.
"""

# ==================  SIGNAL THRESHOLDS ====================
# Individual signal thresholds (0.0-1.0)
# Adjust these to be more lenient or strict per signal

# URL Analysis thresholds
URL_SUSPICIOUS_THRESHOLD = 0.55      # Balanced: Catch suspicious URLs but avoid false positives
URL_CRITICAL_THRESHOLD = 0.80        # High confidence suspicious URL

# Domain Analysis thresholds  
DOMAIN_SUSPICIOUS_THRESHOLD = 0.55   # Balanced: Catch domain spoofing
DOMAIN_CRITICAL_THRESHOLD = 0.80

# Intent Detection thresholds (phishing intent in subject/body)
INTENT_SUSPICIOUS_THRESHOLD = 0.60   # Balanced: Phishing intent threshold
INTENT_CRITICAL_THRESHOLD = 0.85

# Text/Content Analysis thresholds
TEXT_SUSPICIOUS_THRESHOLD = 0.60     # Balanced: Suspicious content threshold
TEXT_CRITICAL_THRESHOLD = 0.85

# VirusTotal detection threshold
VT_SUSPICIOUS_THRESHOLD = 0.50       # VT is very reliable, lower threshold

# Header Authentication (SPF/DKIM/DMARC) threshold
HEADER_SUSPICIOUS_THRESHOLD = 0.60   # Failed authentication


# ================= ENSEMBLE VOTING CONFIG =================
# Minimum signals required to flag as phishing

MIN_SIGNALS_FOR_FLAG_UNKNOWN = 2     # 2+ signals needed for unknown senders
MIN_SIGNALS_FOR_FLAG_WHITELISTED = 2 # 2+ signals needed even for whitelisted

# Special case: VirusTotal + 1 other signal is enough
VT_OVERRIDE_THRESHOLD = 0.75         # VirusTotal override threshold


# ================= FINAL RISK THRESHOLDS =================
# Score-based risk level classification

# For UNKNOWN senders (standard detection)
UNKNOWN_SENDER_HIGH_RISK = 0.55      # Balanced threshold for HIGH risk
UNKNOWN_SENDER_MEDIUM_RISK = 0.35    # Balanced threshold for MEDIUM risk

# For WHITELISTED senders (more lenient)
WHITELISTED_HIGH_RISK = 0.65         # Slightly stricter for known good senders
WHITELISTED_MEDIUM_RISK = 0.45       # Slightly stricter for known good senders


# ================= CONFIDENCE THRESHOLDS =================
# Confidence levels in detection result (0.0-1.0)

MIN_CONFIDENCE_TO_FLAG = 0.60        # Only flag if confidence meets this threshold
HIGH_CONFIDENCE_THRESHOLD = 0.85     # Threshold for "high confidence" classification


# ================= SPECIAL RULES =================
MAX_DOMAIN_AGE_FOR_NEW_DOMAIN = 30   # Days - domains newer than this are considered new
MAX_SUSPICIOUS_URLS_IN_EMAIL = 5     # If more than this many suspicious URLs, high risk

# Whitelist effectiveness
WHITELISTED_DOMAIN_THRESHOLD_REDUCTION = 0.20  # Reduce thresholds by this amount for whitelisted

# ====================  ADVICE FOR TUNING ====================
"""
To REDUCE FALSE POSITIVES (too many legitimate emails flagged):
  - Increase all THRESHOLD values
  - Increase MIN_SIGNALS_FOR_FLAG values 
  - Increase UNKNOWN_SENDER_HIGH_RISK / MEDIUM_RISK
  - Enable whitelist checking and expand whitelist
  - Reduce INTENT_SUSPICIOUS_THRESHOLD and TEXT_SUSPICIOUS_THRESHOLD

To INCREASE TRUE POSITIVES (catch more phishing):
  - Decrease THRESHOLD values
  - Decrease MIN_SIGNALS_FOR_FLAG values
  - Decrease risk level thresholds
  - Expand training data for models
  - Add more heuristics

CURRENT TUNING: Optimized for FALSE POSITIVE REDUCTION
- Requires 2+ concordant signals for unknown senders
- Requires 3+ signals for whitelisted senders
- Uses dynamic thresholds based on sender reputation
"""
