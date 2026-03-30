"""
Phase 11: Classification & Confidence
=======================================
Category determination and confidence calculation.
"""


class ThreatClassifier:
    """Classify threats and determine confidence levels."""

    def classify(self, context: dict) -> dict:
        """Determine category and confidence from risk score and signals."""
        score = context.get('risk_score', 0.0)
        score_result = context.get('score', {})
        strong_signals = score_result.get('strong_signals', 0)
        critical_signals = score_result.get('critical_signals', 0)

        # =================================================================
        # Category Determination
        # =================================================================
        if score >= 0.75:
            category = 'PHISHING'
        elif score >= 0.60:
            if strong_signals >= 2:
                category = 'PHISHING'
            else:
                category = 'SUSPICIOUS'
        elif score >= 0.35:
            category = 'SUSPICIOUS'
        elif score >= 0.20:
            category = 'POTENTIALLY SUSPICIOUS'
        else:
            category = 'SAFE'

        # =================================================================
        # Confidence Calculation
        # =================================================================
        confidence = self._calculate_confidence(
            score, category, context, strong_signals, critical_signals
        )

        return {
            'category': category,
            'confidence': confidence,
            'strong_signals': strong_signals,
        }

    def _calculate_confidence(self, score, category, context, strong_signals, critical_signals):
        """Calculate confidence level."""
        whitelisted = context.get('whitelist', {}).get('whitelisted', False)
        blacklisted = context.get('threat', {}).get('blacklist_status', 'clean') == 'confirmed_phishing'
        brand_lookalike = context.get('brand', {}).get('lookalike_detected', False)
        impersonation_type = context.get('brand', {}).get('impersonation_type', 'none')

        # HIGH confidence scenarios
        if whitelisted and score < 0.20:
            return 'HIGH'
        if blacklisted:
            return 'HIGH'
        if critical_signals >= 3:
            return 'HIGH'
        if brand_lookalike and impersonation_type in ('homograph', 'subdomain_spoofing'):
            return 'HIGH'
        if score > 0.80 or score < 0.10:
            return 'HIGH'
        if strong_signals >= 3:
            return 'HIGH'

        # LOW confidence scenarios
        if strong_signals <= 1 and 0.15 <= score <= 0.45:
            return 'LOW'
        if score_near_threshold(score, [0.20, 0.35, 0.60, 0.75], margin=0.05):
            return 'LOW'

        # MEDIUM otherwise
        return 'MEDIUM'


def score_near_threshold(score, thresholds, margin=0.05):
    """Check if score is within margin of any threshold."""
    for t in thresholds:
        if abs(score - t) <= margin:
            return True
    return False
