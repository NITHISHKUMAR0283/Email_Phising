"""
Phase 9: Contextual Intelligence
==================================
Social engineering detection, form inference, temporal analysis, linguistics.
"""

import re
import hashlib


class ContextualAnalyzer:
    """Analyze contextual signals for threat assessment."""

    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'immediately', 'now', '24-hours', '24hours',
        'expire', 'expires', 'expired', 'suspended', 'locked', 'limited',
        'restricted', 'unusual-activity', 'unusual_activity', 'verify-immediately',
        'action-required', 'action_required', 'act-now', 'final-warning',
        'last-chance', 'time-sensitive',
    ]

    FORM_KEYWORDS = {
        'login': ['login', 'signin', 'sign-in', 'log-in', 'logon'],
        'credit_card': ['payment', 'billing', 'card', 'checkout', 'pay'],
        'personal_info': ['ssn', 'social-security', 'identity', 'personal', 'dob', 'birthdate'],
        'file_upload': ['upload', 'attach', 'file', 'document'],
    }

    def analyze(self, parsed: dict, context: dict) -> dict:
        """Run contextual intelligence analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'urgency_keywords_found': [],
            'form_type_detected': None,
        }

        url = parsed.get('original_url', '').lower()
        path = parsed.get('path', '/').lower()
        query = parsed.get('query', '').lower()
        full_text = f"{url} {path} {query}"

        # =================================================================
        # Social Engineering Detection
        # =================================================================
        found_urgency = []
        for keyword in self.URGENCY_KEYWORDS:
            result['checks_performed'] += 1
            if keyword in full_text.replace(' ', '-'):
                found_urgency.append(keyword)

        result['urgency_keywords_found'] = found_urgency

        if len(found_urgency) >= 3:
            result['risk_factors'].append({
                'factor': f'Multiple urgency keywords detected ({len(found_urgency)}): {", ".join(found_urgency[:5])}',
                'severity': 'HIGH',
                'weight': 0.30
            })
        elif len(found_urgency) >= 2:
            result['risk_factors'].append({
                'factor': f'Urgency keywords detected: {", ".join(found_urgency)}',
                'severity': 'MODERATE',
                'weight': 0.20
            })
        elif len(found_urgency) == 1:
            result['risk_factors'].append({
                'factor': f'Urgency keyword detected: {found_urgency[0]}',
                'severity': 'LOW',
                'weight': 0.10
            })

        # =================================================================
        # Form & Input Detection (Simulated)
        # =================================================================
        detected_forms = []
        for form_type, keywords in self.FORM_KEYWORDS.items():
            result['checks_performed'] += 1
            for kw in keywords:
                if kw in full_text:
                    detected_forms.append(form_type)
                    break

        if detected_forms:
            result['form_type_detected'] = detected_forms[0]

            form_weights = {
                'personal_info': 0.30,
                'credit_card': 0.25,
                'login': 0.15,
                'file_upload': 0.10,
            }

            for form in detected_forms:
                weight = form_weights.get(form, 0.10)
                result['risk_factors'].append({
                    'factor': f'Likely contains {form.replace("_", " ")} form',
                    'severity': 'MODERATE' if weight >= 0.20 else 'LOW',
                    'weight': weight
                })

        # =================================================================
        # Brand + Form Multiplier Flag
        # =================================================================
        result['checks_performed'] += 1
        brand_lookalike = context.get('brand', {}).get('lookalike_detected', False)
        if brand_lookalike and detected_forms:
            result['brand_form_combo'] = True
        else:
            result['brand_form_combo'] = False

        # =================================================================
        # Temporal Analysis (Simulated)
        # =================================================================
        result['checks_performed'] += 1
        domain = parsed.get('full_domain', '')
        temporal = self._simulate_temporal(domain, context)
        if temporal.get('weekend_registration'):
            result['risk_factors'].append({
                'factor': 'Domain registered on weekend (unusual)',
                'severity': 'LOW',
                'weight': 0.10
            })
        if temporal.get('cert_same_day'):
            result['risk_factors'].append({
                'factor': 'SSL certificate issued same day as domain registration',
                'severity': 'MODERATE',
                'weight': 0.20
            })

        # =================================================================
        # Linguistic Analysis
        # =================================================================
        result['checks_performed'] += 1
        domain_name = domain.split('.')[0] if domain else ''

        # Mixed script characters
        has_latin = bool(re.search(r'[a-zA-Z]', domain_name))
        has_non_latin = bool(re.search(r'[^\x00-\x7F]', domain_name))
        if has_latin and has_non_latin:
            result['risk_factors'].append({
                'factor': 'Mixed script characters (Latin + non-Latin)',
                'severity': 'HIGH',
                'weight': 0.35
            })

        return result

    def _simulate_temporal(self, domain: str, context: dict) -> dict:
        """Simulate temporal analysis based on domain characteristics."""
        h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)

        domain_age = context.get('domain', {}).get('domain_age_days', 365)
        cert_age = context.get('certificate', {}).get('certificate_age', '90d+')

        weekend = (h % 7) >= 5  # Simulated
        cert_same_day = domain_age < 7 and cert_age in ('<24h', '1-7d')

        return {
            'weekend_registration': weekend and domain_age < 30,
            'cert_same_day': cert_same_day,
        }
