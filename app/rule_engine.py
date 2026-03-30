"""
Rule-based feature extraction for phishing detection.
Combines with ML for dramatic accuracy improvement.

Philosophy: ML models are good but can be confused.
Rules catch the most obvious patterns with 100% confidence.
"""

import re
from typing import Dict, Any, List, Tuple
from datetime import datetime


class PhishingRuleEngine:
    """
    Rule-based phishing detection engine.
    Applies deterministic rules to catch obvious threats.
    """
    
    # Extreme phishing keywords (very high confidence)
    EXTREME_PHISHING_KEYWORDS = [
        "verify your account immediately",
        "confirm your identity now",
        "account will be closed",
        "click here to verify",
        "verify your password",
        "reset your password immediately",
        "unauthorized access",
        "unusual activity detected",
        "account suspended",
        "action required immediately",
        "verify or account closes",
        "confirm now or lose access",
    ]
    
    # High confidence phishing indicators
    HIGH_CONFIDENCE_KEYWORDS = [
        "urgent", "verify", "confirm", "click here", "click now",
        "action required", "validate", "authenticate", "reset password",
        "update information", "confirm identity", "unusual activity",
    ]
    
    # Phishing-specific URL patterns
    PHISHING_URL_PATTERNS = [
        r"login.*verify",
        r"secure.*update",
        r"confirm.*password",
        r"verify.*account",
        r"urgent.*click",
        r"action.*required",
    ]
    
    # Legitimate context keywords (reduce score if present)
    LEGITIMATE_KEYWORDS = [
        "order confirmation", "shipping", "delivery",
        "thank you for your purchase", "invoice", "receipt",
        "course material", "lesson", "tutorial",
        "your github activity", "new follower", "pull request",
    ]
    
    def __init__(self):
        """Initialize rule engine."""
        self.rules_applied = []
        self.score_boost = 0.0
        self.score_penalty = 0.0
    
    def rule_check_extreme_keywords(self, text: str) -> Tuple[float, str]:
        """
        Check for extreme phishing keywords (very high confidence).
        Score boost: +0.4
        """
        text_lower = text.lower()
        
        for keyword in self.EXTREME_PHISHING_KEYWORDS:
            if keyword in text_lower:
                self.rules_applied.append(f"Extreme phishing keyword: '{keyword}'")
                return 0.4, f"Extreme phishing keyword detected: '{keyword}'"
        
        return 0.0, ""
    
    def rule_check_high_confidence_keywords(self, text: str) -> Tuple[float, str]:
        """
        Check for high confidence phishing keywords.
        Score boost: +0.2 per keyword (max +0.5)
        """
        text_lower = text.lower()
        count = 0
        matched = []
        
        for keyword in self.HIGH_CONFIDENCE_KEYWORDS:
            # Count only if word boundary (not part of larger word)
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower, re.IGNORECASE):
                count += 1
                matched.append(keyword)
        
        boost = min(0.5, count * 0.2)
        
        if count > 0:
            keywords_str = ", ".join(matched[:3])  # Show first 3
            self.rules_applied.append(f"Found {count} phishing keywords: {keywords_str}")
            return boost, f"Found {count} phishing trigger words"
        
        return 0.0, ""
    
    def rule_check_url_mismatch(self, sender: str, urls: List[str]) -> Tuple[float, str]:
        """
        Check if URLs don't match claimed sender domain.
        Score boost: +0.3 (strong indicator)
        """
        if not sender or not urls:
            return 0.0, ""
        
        try:
            # Extract domain from sender email
            sender_domain = sender.split("@")[1].split(">")[0].lower()
            
            for url in urls:
                # Extract domain from URL
                url_parts = url.lower().split("/")
                url_domain = url_parts[2].lstrip("www.") if len(url_parts) > 2 else ""
                
                # Check if mismatch
                if url_domain and sender_domain not in url_domain and url_domain not in sender_domain:
                    self.rules_applied.append(f"URL domain mismatch: sender={sender_domain}, url={url_domain}")
                    return 0.3, f"URL domain mismatch - sender uses {sender_domain}, but URL links to {url_domain}"
        
        except Exception as e:
            pass
        
        return 0.0, ""
    
    def rule_check_domain_age(self, domain_age_days: int) -> Tuple[float, str]:
        """
        Check domain age (very new domains are high risk).
        Boost: +0.35 if < 7 days (brand new)
        Boost: +0.2 if < 30 days (very new)
        Boost: +0.1 if < 60 days (new)
        """
        if domain_age_days is None or domain_age_days < 0:
            return 0.0, ""
        
        if domain_age_days < 7:
            self.rules_applied.append(f"Brand new domain: {domain_age_days} days old")
            return 0.35, f"Domain created only {domain_age_days} days ago (very suspicious)"
        
        elif domain_age_days < 30:
            self.rules_applied.append(f"Very new domain: {domain_age_days} days old")
            return 0.2, f"Domain created {domain_age_days} days ago (suspicious)"
        
        elif domain_age_days < 60:
            self.rules_applied.append(f"New domain: {domain_age_days} days old")
            return 0.1, f"Domain created {domain_age_days} days ago (slightly suspicious)"
        
        return 0.0, ""
    
    def rule_check_spf_dkim_dmarc(self, spf: str, dkim: str, dmarc: str) -> Tuple[float, str]:
        """
        Check authentication protocol status.
        Boost: +0.25 per failure (max +0.75)
        """
        boost = 0.0
        failures = []
        
        if spf in ["fail", "softfail"]:
            boost += 0.15
            failures.append("SPF failed")
        
        if dkim in ["fail", "softfail"]:
            boost += 0.25
            failures.append("DKIM failed")
        
        if dmarc in ["fail", "softfail"]:
            boost += 0.25
            failures.append("DMARC failed")
        
        if failures:
            self.rules_applied.append(f"Auth failures: {', '.join(failures)}")
            return min(0.75, boost), f"Authentication failed: {', '.join(failures)}"
        
        return 0.0, ""
    
    def rule_check_vt_malicious(self, vt_malicious_count: int) -> Tuple[float, str]:
        """
        Check VirusTotal malicious count.
        Very high confidence if engines flagged it.
        """
        if vt_malicious_count is None or vt_malicious_count == 0:
            return 0.0, ""
        
        if vt_malicious_count >= 20:
            self.rules_applied.append(f"VT: {vt_malicious_count} engines flagged URL")
            return 0.5, f"VirusTotal: {vt_malicious_count} antivirus engines flagged as malicious"
        
        elif vt_malicious_count >= 10:
            self.rules_applied.append(f"VT: {vt_malicious_count} engines flagged URL")
            return 0.35, f"VirusTotal: {vt_malicious_count} engines flagged URL"
        
        elif vt_malicious_count >= 5:
            self.rules_applied.append(f"VT: {vt_malicious_count} engines flagged URL")
            return 0.2, f"VirusTotal: {vt_malicious_count} engines flagged URL"
        
        return 0.0, ""
    
    def rule_check_sender_spoofing(self, from_addr: str, return_path: str) -> Tuple[float, str]:
        """
        Check if sender appears to spoof known brand.
        Score boost: +0.25
        """
        known_brands = {
            "paypal": ["paypal.com"],
            "amazon": ["amazon.com"],
            "apple": ["apple.com"],
            "microsoft": ["microsoft.com"],
            "google": ["google.com"],
            "bank": ["bankofamerica.com", "wellsfargo.com", "chase.com"],
            "ebay": ["ebay.com"],
        }
        
        if not from_addr:
            return 0.0, ""
        
        from_lower = from_addr.lower()
        
        for brand, legit_domains in known_brands.items():
            # Check if display name claims to be brand
            if brand in from_lower or f'"{brand}' in from_lower:
                # Check if actual domain is NOT the legitimate domain
                actual_domain = from_addr.split("@")[1].split(">")[0].lower() if "@" in from_addr else ""
                
                is_legit = any(domain in actual_domain for domain in legit_domains)
                
                if not is_legit and actual_domain:
                    self.rules_applied.append(f"Brand spoofing: claims {brand} but domain is {actual_domain}")
                    return 0.25, f"Display name spoofs '{brand}' but sender domain is '{actual_domain}'"
        
        return 0.0, ""
    
    def rule_check_legitimate_keywords(self, text: str) -> Tuple[float, str]:
        """
        Check for legitimate transaction keywords (reduce false positives).
        Score penalty: -0.2
        """
        text_lower = text.lower()
        count = 0
        matched = []
        
        for keyword in self.LEGITIMATE_KEYWORDS:
            if keyword in text_lower:
                count += 1
                matched.append(keyword)
        
        if count >= 2:  # Only penalize if multiple legitimate indicators
            penalty = -0.2
            keywords_str = ", ".join(matched[:2])
            self.rules_applied.append(f"Legitimate indicators: {keywords_str}")
            return penalty, f"Contains legitimate transaction indicators ({keywords_str})"
        
        return 0.0, ""
    
    def apply_all_rules(self, email: Dict[str, Any], header_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply all rules and return dynamic boost for ensemble.
        
        Args:
            email: Email data {subject, body, sender, urls}
            header_data: Header analysis {spf, dkim, dmarc, domain_age, vt_malicious}
        
        Returns:
            Dict with rules applied and score adjustments
        """
        self.rules_applied = []
        self.score_boost = 0.0
        self.score_penalty = 0.0
        findings = []
        
        text = email.get("subject", "") + " " + email.get("body", "")
        sender = email.get("sender", "")
        urls = email.get("urls", [])
        
        # Rule 1: Extreme phishing keywords (highest confidence)
        boost, finding = self.rule_check_extreme_keywords(text)
        self.score_boost = max(self.score_boost, boost)
        if finding:
            findings.append(finding)
        
        # Rule 2: High confidence keywords
        boost, finding = self.rule_check_high_confidence_keywords(text)
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 3: URL mismatch
        boost, finding = self.rule_check_url_mismatch(sender, urls)
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 4: Domain age (if available)
        domain_age = header_data.get("domain_age")
        boost, finding = self.rule_check_domain_age(domain_age)
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 5: Authentication protocols
        boost, finding = self.rule_check_spf_dkim_dmarc(
            header_data.get("spf", "none"),
            header_data.get("dkim", "none"),
            header_data.get("dmarc", "none")
        )
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 6: VirusTotal malicious count
        vt_malicious = header_data.get("vt_malicious_count", 0)
        boost, finding = self.rule_check_vt_malicious(vt_malicious)
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 7: Sender spoofing
        return_path = header_data.get("return_path", "")
        boost, finding = self.rule_check_sender_spoofing(sender, return_path)
        self.score_boost += boost
        if finding:
            findings.append(finding)
        
        # Rule 8: Legitimate keywords (reduce false positives)
        penalty, finding = self.rule_check_legitimate_keywords(text)
        self.score_penalty = penalty
        if finding:
            findings.append(finding)
        
        # Cap boosts at reasonable levels
        self.score_boost = min(1.0, self.score_boost)
        self.score_penalty = max(-0.3, self.score_penalty)
        
        return {
            "score_boost": self.score_boost,
            "score_penalty": self.score_penalty,
            "net_adjustment": self.score_boost + self.score_penalty,
            "rules_applied": self.rules_applied,
            "findings": findings
        }


def apply_dynamic_weighting(
    url_score: float,
    domain_score: float,
    intent_score: float,
    text_score: float,
    vt_score: float,
    email_data: Dict[str, Any],
    header_data: Dict[str, Any]
) -> Tuple[float, Dict[str, Any]]:
    """
    Apply dynamic weighting based on conditions.
    Different conditions require different weight distributions.
    
    Args:
        url_score, domain_score, intent_score, text_score, vt_score: Base ML scores
        email_data: {subject, body, sender, urls}
        header_data: {spf, dkim, dmarc, domain_age, vt_malicious_count}
    
    Returns:
        (final_score, weighting_info)
    """
    
    # Apply rule-based features
    rule_engine = PhishingRuleEngine()
    rules = rule_engine.apply_all_rules(email_data, header_data)
    
    # Base weights
    weights = {
        "url": 0.35,
        "domain": 0.20,
        "intent": 0.15,
        "text": 0.15,
        "vt": 0.15
    }
    
    # Dynamic weighting adjustments
    
    # Condition 1: New domain (< 30 days) → Trust domain analysis more
    domain_age = header_data.get("domain_age")
    if domain_age is not None and domain_age < 30:
        weights["domain"] = 0.30
        weights["text"] = 0.10
        weights["intent"] = 0.10
    
    # Condition 2: Auth failures (SPF/DKIM fail) → Trust auth more
    if header_data.get("spf") in ["fail", "softfail"] or \
       header_data.get("dkim") in ["fail", "softfail"]:
        weights["domain"] = 0.25
        weights["url"] = 0.30
    
    # Condition 3: VT flagged (20+ engines) → Trust VT heavily
    vt_malicious = header_data.get("vt_malicious_count", 0)
    if vt_malicious >= 20:
        weights["vt"] = 0.40
        weights["url"] = 0.25
        weights["domain"] = 0.20
        weights["intent"] = 0.10
        weights["text"] = 0.05
    
    # Condition 4: Contains extreme phishing keywords → Trust intent/text more
    extreme_keywords = [
        "verify your account immediately",
        "click here to verify",
        "reset your password immediately",
    ]
    has_extreme = any(kw in email_data.get("body", "").lower() for kw in extreme_keywords)
    if has_extreme:
        weights["intent"] = 0.25
        weights["text"] = 0.25
        weights["url"] = 0.25
        weights["domain"] = 0.15
        weights["vt"] = 0.10
    
    # Re-normalize weights to sum to 1.0
    total = sum(weights.values())
    weights = {k: v/total for k, v in weights.items()}
    
    # Calculate weighted score
    base_score = (
        weights["url"] * url_score +
        weights["domain"] * domain_score +
        weights["intent"] * intent_score +
        weights["text"] * text_score +
        (weights["vt"] * vt_score if vt_score > 0 else 0)
    )
    
    # Apply rule-based adjustments
    final_score = base_score + rules["score_boost"] + rules["score_penalty"]
    final_score = max(0.0, min(1.0, final_score))
    
    return final_score, {
        "weights": weights,
        "base_score": base_score,
        "rule_adjustments": rules,
        "final_score": final_score
    }
