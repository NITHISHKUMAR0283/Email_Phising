"""
Phase 12: False Positive Prevention Layer
===========================================
Six verification checks to minimize false positives.
"""


class FalsePositivePrevention:
    """Run false-positive prevention checks before final classification."""

    def verify(self, context: dict) -> dict:
        """Run all 6 FP prevention checks."""
        result = {
            'checks_performed': 0,
            'category_override': None,
            'score_override': None,
            'confidence_override': None,
            'checks_triggered': [],
        }

        category = context['classification']['category']
        confidence = context['classification']['confidence']
        score = context['risk_score']
        whitelisted = context.get('whitelist', {}).get('whitelisted', False)
        whitelist_tier = context.get('whitelist', {}).get('whitelist_tier')
        brand_lookalike = context.get('brand', {}).get('lookalike_detected', False)
        score_result = context.get('score', {})
        strong_signals = score_result.get('strong_signals', 0)
        positive_count = score_result.get('positive_factor_count', 0)
        domain = context.get('domain', {})
        cert = context.get('certificate', {})
        threat = context.get('threat', {})

        # =================================================================
        # CHECK 1: Whitelist Override
        # =================================================================
        result['checks_performed'] += 1
        if whitelisted and whitelist_tier == 1 and score < 0.60:
            result['category_override'] = 'SAFE'
            result['score_override'] = 0.0
            result['confidence_override'] = 'HIGH'
            result['checks_triggered'].append('CHECK 1: Whitelist override applied')
            return result  # Short circuit

        # =================================================================
        # CHECK 2: Single Signal Prevention
        # =================================================================
        result['checks_performed'] += 1
        if positive_count <= 1 and score < 0.40:
            if category in ('SUSPICIOUS', 'PHISHING'):
                result['category_override'] = 'POTENTIALLY SUSPICIOUS'
                result['checks_triggered'].append('CHECK 2: Single signal downgrade')

        # =================================================================
        # CHECK 3: Context Validation
        # =================================================================
        result['checks_performed'] += 1
        if brand_lookalike:
            age_days = domain.get('domain_age_days', 0)
            reputation = threat.get('reputation_score', 50)
            ssl_valid = cert.get('ssl_status') == 'valid'
            ca_trusted = cert.get('ca_trusted', False)

            if age_days > 730 and reputation >= 70 and ssl_valid and ca_trusted:
                # Established domain wrongly flagged as brand lookalike
                if category == 'PHISHING':
                    result['category_override'] = 'SUSPICIOUS'
                    result['checks_triggered'].append('CHECK 3: Established domain downgrade')
                elif category == 'SUSPICIOUS':
                    result['category_override'] = 'POTENTIALLY SUSPICIOUS'
                    result['checks_triggered'].append('CHECK 3: Established domain downgrade')

        # =================================================================
        # CHECK 4: TLD Context
        # =================================================================
        result['checks_performed'] += 1
        tld_risk = domain.get('tld_risk_level', 'NEUTRAL')
        if tld_risk in ('HIGH', 'CRITICAL'):
            age_days = domain.get('domain_age_days', 0)
            reputation = threat.get('reputation_score', 50)
            if age_days > 365 and reputation >= 60:
                # Established domain on risky TLD - reduce TLD impact
                result['checks_triggered'].append('CHECK 4: TLD risk reduced for established domain')
                # We don't override category but note it

        # =================================================================
        # CHECK 5: Legitimate Use Cases
        # =================================================================
        result['checks_performed'] += 1
        full_domain = context.get('parsed', {}).get('full_domain', '')

        # CDN/cloud hostnames
        if domain.get('is_cdn', False) and category in ('SUSPICIOUS', 'POTENTIALLY SUSPICIOUS'):
            if not brand_lookalike:
                result['category_override'] = 'SAFE'
                result['score_override'] = max(0, score - 0.20)
                result['checks_triggered'].append('CHECK 5: CDN/cloud hostname')

        # URL shorteners from trusted platforms
        shortener = context.get('redirect', {}).get('shortener_used', False)
        shortener_name = context.get('redirect', {}).get('shortener_name', '')
        trusted_shorteners = {'t.co', 'youtu.be', 'amzn.to', 'lnkd.in', 'goo.gl'}
        if shortener and shortener_name in trusted_shorteners:
            if category == 'SUSPICIOUS':
                result['category_override'] = 'POTENTIALLY SUSPICIOUS'
                result['checks_triggered'].append('CHECK 5: Trusted platform shortener')

        # =================================================================
        # CHECK 6: Confidence Gate
        # =================================================================
        result['checks_performed'] += 1
        final_category = result['category_override'] or category
        final_confidence = result['confidence_override'] or confidence

        if final_confidence == 'LOW' and final_category == 'PHISHING':
            result['category_override'] = 'SUSPICIOUS'
            result['checks_triggered'].append('CHECK 6: Low confidence PHISHING downgraded')

        return result
