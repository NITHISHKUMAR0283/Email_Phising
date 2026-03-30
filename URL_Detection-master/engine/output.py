"""
Phase 13: Output Generation
=============================
Comprehensive JSON output with all analysis fields populated.
"""

from datetime import datetime, timezone


class OutputGenerator:
    """Generate the final structured output from analysis context."""

    def generate(self, context: dict) -> dict:
        """Generate comprehensive JSON output."""
        parsed = context.get('parsed', {})
        domain = context.get('domain', {})
        brand = context.get('brand', {})
        structural = context.get('structural', {})
        redirect = context.get('redirect', {})
        cert = context.get('certificate', {})
        threat = context.get('threat', {})
        whitelist = context.get('whitelist', {})
        contextual = context.get('contextual', {})
        classification = context.get('classification', {})
        score_result = context.get('score', {})
        fp_check = context.get('fp_check', {})

        # Final category and score (after FP prevention)
        category = classification.get('category', 'SAFE')
        confidence = classification.get('confidence', 'MEDIUM')
        risk_score = context.get('risk_score', 0.0)

        # Build risk factors list (only positive-weight factors for output)
        risk_factors_output = []
        for rf in context.get('risk_factors', []):
            if rf.get('weight', 0) > 0:
                risk_factors_output.append({
                    'factor': rf['factor'],
                    'severity': rf.get('severity', 'LOW'),
                    'weight': round(rf.get('weight', 0), 3)
                })

        # Sort by weight descending
        risk_factors_output.sort(key=lambda x: x['weight'], reverse=True)

        # Build flags
        flags = []
        for rf in risk_factors_output[:10]:  # Top 10 flags
            flags.append(rf['factor'])

        # Add FP check triggers
        if fp_check.get('checks_triggered'):
            for check in fp_check['checks_triggered']:
                flags.append(f'[FP Prevention] {check}')

        # Generate explanation
        explanation = self._generate_explanation(
            category, confidence, risk_score, risk_factors_output,
            domain, brand, cert, threat, whitelist, score_result
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(category, brand, cert)

        # Combine suspicious keywords
        all_keywords = (
            structural.get('suspicious_keywords', []) +
            contextual.get('urgency_keywords_found', [])
        )

        output = {
            'url': parsed.get('original_url', ''),
            'category': category,
            'risk_score': round(risk_score, 3),
            'confidence': confidence,

            'domain_analysis': {
                'root_domain': domain.get('root_domain', ''),
                'full_domain': parsed.get('full_domain', ''),
                'tld': domain.get('tld', ''),
                'subdomain_count': domain.get('subdomain_count', 0),
                'is_ip_address': domain.get('is_ip_address', False),
                'domain_age_estimate': domain.get('domain_age_estimate', 'unknown'),
                'domain_entropy': domain.get('domain_entropy', 0.0),
                'tld_risk_level': domain.get('tld_risk_level', 'NEUTRAL'),
            },

            'security_analysis': {
                'protocol': parsed.get('protocol', 'http'),
                'ssl_status': cert.get('ssl_status', 'none'),
                'certificate_age': cert.get('certificate_age', 'unknown'),
                'port': parsed.get('port'),
            },

            'threat_intelligence': {
                'blacklist_status': threat.get('blacklist_status', 'clean'),
                'reputation_score': threat.get('reputation_score', 50),
                'known_threat': threat.get('known_threat', False),
                'first_seen': threat.get('first_seen', 'unknown'),
            },

            'brand_analysis': {
                'potential_target': brand.get('potential_target'),
                'similarity_score': brand.get('similarity_score'),
                'impersonation_type': brand.get('impersonation_type', 'none'),
                'lookalike_detected': brand.get('lookalike_detected', False),
            },

            'behavioral_indicators': {
                'url_length': parsed.get('url_length', len(parsed.get('original_url', ''))),
                'encoding_count': parsed.get('encoding_count', 0),
                'suspicious_keywords': all_keywords,
                'redirect_detected': redirect.get('redirect_detected', False),
                'shortener_used': redirect.get('shortener_used', False),
            },

            'risk_factors': risk_factors_output,

            'flags': flags,

            'explanation': explanation,

            'recommendations': recommendations,

            'scoring_details': {
                'base_score': score_result.get('base_score', 0.0),
                'multiplier': score_result.get('multiplier', 1.0),
                'multiplier_reasons': score_result.get('multiplier_reasons', []),
                'positive_factors': score_result.get('positive_factor_count', 0),
                'negative_factors': score_result.get('negative_factor_count', 0),
                'critical_signals': score_result.get('critical_signals', 0),
                'high_signals': score_result.get('high_signals', 0),
            },

            'false_positive_checks': {
                'checks_triggered': fp_check.get('checks_triggered', []),
                'category_overridden': fp_check.get('category_override') is not None,
            },

            'metadata': {
                'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                'detection_methods_used': context.get('detection_methods', []),
                'total_checks_performed': context.get('checks_performed', 0),
            },
        }

        return output

    def _generate_explanation(self, category, confidence, score, risk_factors,
                              domain, brand, cert, threat, whitelist, score_result):
        """Generate human-readable explanation."""
        parts = []

        if category == 'SAFE':
            if whitelist.get('whitelisted'):
                tier = whitelist.get('whitelist_tier', 1)
                parts.append(f"This URL belongs to a Tier {tier} whitelisted domain and is verified as legitimate.")
            else:
                parts.append("This URL shows no significant threat indicators.")
            parts.append(f"Risk score: {score:.3f} (Confidence: {confidence}).")

        elif category == 'POTENTIALLY SUSPICIOUS':
            parts.append("This URL has minor risk indicators that warrant caution.")
            if risk_factors:
                parts.append(f"Primary concern: {risk_factors[0]['factor']}.")
            parts.append(f"Risk score: {score:.3f} (Confidence: {confidence}).")

        elif category == 'SUSPICIOUS':
            parts.append("This URL exhibits multiple suspicious characteristics.")
            top_factors = [rf['factor'] for rf in risk_factors[:3]]
            if top_factors:
                parts.append(f"Key indicators: {'; '.join(top_factors)}.")
            parts.append(f"Risk score: {score:.3f} with {score_result.get('strong_signals', 0)} strong threat signals.")

        elif category == 'PHISHING':
            parts.append("⚠ HIGH THREAT: This URL is classified as a phishing attempt.")
            if brand.get('lookalike_detected'):
                target = brand.get('potential_target', 'unknown brand')
                imp_type = brand.get('impersonation_type', 'unknown')
                parts.append(f"Targets: {target} (via {imp_type}).")
            top_factors = [rf['factor'] for rf in risk_factors[:3]]
            if top_factors:
                parts.append(f"Critical evidence: {'; '.join(top_factors)}.")
            parts.append(f"Risk score: {score:.3f} (Confidence: {confidence}).")

        # Add scoring detail
        if score_result.get('multiplier', 1.0) > 1.0:
            parts.append(f"Risk multiplier {score_result['multiplier']}× applied: {', '.join(score_result.get('multiplier_reasons', []))}.")

        return ' '.join(parts)

    def _generate_recommendations(self, category, brand, cert):
        """Generate actionable recommendations."""
        if category == 'SAFE':
            return {
                'user_action': 'This URL appears safe to visit. Standard security practices apply.',
                'technical_details': 'No significant threat indicators detected. Routine monitoring recommended.'
            }
        elif category == 'POTENTIALLY SUSPICIOUS':
            return {
                'user_action': 'Exercise caution. Verify the URL source before entering any personal information.',
                'technical_details': 'Minor risk factors detected. Monitor for changes in threat intelligence.'
            }
        elif category == 'SUSPICIOUS':
            return {
                'user_action': 'Do NOT enter any personal information. Verify the URL through official channels before proceeding.',
                'technical_details': 'Multiple risk indicators detected. Recommend blocking in web proxy and adding to watchlist.'
            }
        elif category == 'PHISHING':
            target = brand.get('potential_target', 'unknown')
            return {
                'user_action': f'DO NOT visit this URL. This is likely a phishing attack targeting {target}. Report to security team immediately.',
                'technical_details': f'Confirmed phishing indicators. Recommend immediate block, DNS sinkhole, and user awareness alert. Target brand: {target}.'
            }
        return {
            'user_action': 'Unable to determine safety. Exercise extreme caution.',
            'technical_details': 'Insufficient data for classification.'
        }
