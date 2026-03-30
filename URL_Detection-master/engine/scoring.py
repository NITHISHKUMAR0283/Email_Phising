"""
Phase 10: Advanced Scoring Algorithm
======================================
Risk score accumulation with multipliers and clamping.
"""


class RiskScorer:
    """Calculate weighted risk scores from accumulated factors."""

    def calculate(self, context: dict) -> dict:
        """Calculate the final risk score from all accumulated risk factors."""
        risk_factors = context.get('risk_factors', [])
        
        # Accumulate base score
        base_score = 0.0
        positive_factors = []
        negative_factors = []
        
        for factor in risk_factors:
            weight = factor.get('weight', 0)
            base_score += weight
            if weight > 0:
                positive_factors.append(factor)
            elif weight < 0:
                negative_factors.append(factor)

        # =================================================================
        # Apply Multipliers
        # =================================================================
        multiplier = 1.0
        multiplier_reasons = []

        # Brand lookalike + login form
        brand_lookalike = context.get('brand', {}).get('lookalike_detected', False)
        has_login_form = context.get('contextual', {}).get('form_type_detected') in ('login', 'credit_card')
        brand_form_combo = context.get('contextual', {}).get('brand_form_combo', False)

        if brand_lookalike and (has_login_form or brand_form_combo):
            multiplier *= 1.4
            multiplier_reasons.append('Brand lookalike + login/payment form (×1.4)')

        # New domain + high risk TLD + suspicious keywords
        domain = context.get('domain', {})
        is_new = domain.get('domain_age_estimate', '') in ('<7d', '7-30d')
        is_risky_tld = domain.get('tld_risk_level', 'NEUTRAL') in ('CRITICAL', 'HIGH')
        has_suspicious_kw = len(context.get('structural', {}).get('suspicious_keywords', [])) > 0

        if is_new and is_risky_tld and has_suspicious_kw:
            multiplier *= 1.3
            multiplier_reasons.append('New domain + risky TLD + suspicious keywords (×1.3)')

        # Subdomain spoofing + SSL issues
        is_subdomain_spoof = context.get('brand', {}).get('impersonation_type') == 'subdomain_spoofing'
        has_ssl_issues = context.get('certificate', {}).get('ssl_status', 'none') in ('self-signed', 'expired', 'invalid', 'none')

        if is_subdomain_spoof and has_ssl_issues:
            multiplier *= 1.5
            multiplier_reasons.append('Subdomain spoofing + SSL issues (×1.5)')

        # Apply multiplier
        final_score = base_score * multiplier

        # --- Shortener Minimum Floor (ENHANCED) ---
        # Ensure shorteners don't drop to "SAFE" (0.0) regardless of discounts
        if context.get('redirect', {}).get('shortener_used', False):
            final_score = max(0.22, final_score)

        # Clamp to [0.0, 1.0]
        final_score = max(0.0, min(1.0, final_score))

        # Count strong signals
        critical_count = sum(1 for f in positive_factors if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in positive_factors if f.get('severity') == 'HIGH')
        strong_signals = critical_count + high_count

        return {
            'base_score': round(base_score, 4),
            'multiplier': round(multiplier, 2),
            'multiplier_reasons': multiplier_reasons,
            'final_score': round(final_score, 3),
            'positive_factor_count': len(positive_factors),
            'negative_factor_count': len(negative_factors),
            'critical_signals': critical_count,
            'high_signals': high_count,
            'strong_signals': strong_signals,
        }
