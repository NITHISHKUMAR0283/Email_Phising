"""
Phase 7: Threat Intelligence Simulation
=========================================
Simulated blacklist, reputation scoring, and historical pattern analysis.
"""

import hashlib
from .tld_data import CRITICAL_RISK_TLDS, HIGH_RISK_TLDS


class ThreatIntelligence:
    """Simulate multi-source threat intelligence checks."""

    # Simulated known-bad patterns (not real blacklists)
    KNOWN_BAD_PATTERNS = [
        'phish', 'scam', 'malware', 'hack', 'crack', 'warez',
        'free-money', 'lottery', 'prize', 'winner', 'bitcoin-double',
        'crypto-giveaway', 'account-verify', 'secure-login',
    ]

    def analyze(self, parsed: dict, domain_result: dict, brand_result: dict) -> dict:
        """Run threat intelligence analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'blacklist_status': 'clean',
            'reputation_score': 50,  # 0-100, 100 = most reputable
            'known_threat': False,
            'first_seen': 'unknown',
        }

        domain = parsed.get('full_domain', '')
        root_domain = domain_result.get('root_domain', domain)

        # =================================================================
        # Blacklist Simulation
        # =================================================================
        result['checks_performed'] += 3  # PhishTank, OpenPhish, APWG

        # Check for known-bad patterns in domain
        domain_lower = domain.lower()
        for pattern in self.KNOWN_BAD_PATTERNS:
            if pattern in domain_lower:
                result['blacklist_status'] = 'flagged'
                result['known_threat'] = True
                result['risk_factors'].append({
                    'factor': f'Domain contains known malicious pattern: "{pattern}"',
                    'severity': 'HIGH',
                    'weight': 0.45
                })
                break

        # Deterministic "blacklist" based on suspicious combinations
        has_brand_lookalike = brand_result.get('lookalike_detected', False)
        is_suspicious_tld = domain_result.get('tld_risk_level', 'NEUTRAL') in ('CRITICAL', 'HIGH')
        is_new_domain = domain_result.get('domain_age_estimate', '') in ('<7d', '7-30d')

        result['checks_performed'] += 1
        if has_brand_lookalike and is_suspicious_tld and is_new_domain:
            result['blacklist_status'] = 'confirmed_phishing'
            result['known_threat'] = True
            result['risk_factors'].append({
                'factor': 'Simulated blacklist: brand lookalike + suspicious TLD + new domain',
                'severity': 'CRITICAL',
                'weight': 0.70
            })
        elif has_brand_lookalike and is_new_domain:
            result['blacklist_status'] = 'flagged'
            result['known_threat'] = True
            result['risk_factors'].append({
                'factor': 'Simulated threat feed: brand lookalike + newly registered domain',
                'severity': 'HIGH',
                'weight': 0.35
            })

        # =================================================================
        # Reputation Scoring (Simulated)
        # =================================================================
        result['checks_performed'] += 3  # Google SB, SmartScreen, Talos

        reputation = self._simulate_reputation(domain, domain_result, brand_result)
        result['reputation_score'] = reputation['score']

        if reputation['score'] < 20:
            result['risk_factors'].append({
                'factor': f'Very low reputation score ({reputation["score"]}/100)',
                'severity': 'CRITICAL',
                'weight': 0.65
            })
        elif reputation['score'] < 40:
            result['risk_factors'].append({
                'factor': f'Low reputation score ({reputation["score"]}/100)',
                'severity': 'HIGH',
                'weight': 0.40
            })
        elif reputation['score'] < 60:
            result['risk_factors'].append({
                'factor': f'Mixed reputation signals ({reputation["score"]}/100)',
                'severity': 'MODERATE',
                'weight': 0.20
            })
        elif reputation['score'] >= 80:
            result['risk_factors'].append({
                'factor': f'Good reputation score ({reputation["score"]}/100)',
                'severity': 'LOW',
                'weight': -0.15
            })

        # =================================================================
        # First Seen Simulation
        # =================================================================
        result['checks_performed'] += 1
        age_days = domain_result.get('domain_age_days', 365)
        if age_days < 7:
            result['first_seen'] = '<7d'
            result['risk_factors'].append({
                'factor': 'First seen in threat feeds within last 7 days',
                'severity': 'MODERATE',
                'weight': 0.25
            })
        elif age_days < 30:
            result['first_seen'] = '7-30d'
        else:
            result['first_seen'] = '30d+'

        # =================================================================
        # Historical Pattern Analysis
        # =================================================================
        result['checks_performed'] += 1
        if self._check_domain_parking(domain):
            result['risk_factors'].append({
                'factor': 'Domain parking indicators detected',
                'severity': 'MODERATE',
                'weight': 0.20
            })

        # Clean history bonus
        if age_days > 365 and result['reputation_score'] >= 70:
            result['risk_factors'].append({
                'factor': 'Clean history for over 1 year',
                'severity': 'LOW',
                'weight': -0.10
            })

        return result

    def _simulate_reputation(self, domain: str, domain_result: dict, brand_result: dict) -> dict:
        """Simulate multi-source reputation check."""
        base_score = 50

        # Well-known domains get high reputation
        well_known = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'youtube.com', 'netflix.com', 'paypal.com',
            'github.com', 'linkedin.com', 'twitter.com', 'reddit.com',
            'wikipedia.org', 'instagram.com', 'whatsapp.com', 'yahoo.com',
            'outlook.com', 'live.com', 'office.com', 'stripe.com',
            'spotify.com', 'cloudflare.com',
        }

        parts = domain.split('.')
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

        # PRIVATE IP EXEMPTION: Local devices are not inherently threats
        is_private_ip = False
        if domain_result.get('is_ip_address'):
            # Simple check for common private ranges
            if domain.startswith('192.168.') or domain.startswith('10.') or domain.startswith('127.'):
                is_private_ip = True
            elif domain.startswith('172.') and len(parts) >= 2:
                oct2 = int(parts[1]) if parts[1].isdigit() else 0
                if 16 <= oct2 <= 31:
                    is_private_ip = True
        
        if is_private_ip:
            return {'score': 75} # Neutral-Safe for local devices

        for wd in well_known:
            if domain.endswith(wd) or root == wd:
                return {'score': 95}

        # Adjust based on domain characteristics
        tld_risk = domain_result.get('tld_risk_level', 'NEUTRAL')
        if tld_risk == 'CRITICAL':
            base_score -= 30
        elif tld_risk == 'HIGH':
            base_score -= 20
        elif tld_risk == 'TRUSTED':
            base_score += 20

        # Domain age
        age_days = domain_result.get('domain_age_days', 365)
        if age_days < 7:
            base_score -= 25
        elif age_days < 30:
            base_score -= 15
        elif age_days > 365:
            base_score += 15

        # Brand lookalike
        if brand_result.get('lookalike_detected'):
            base_score -= 25

        # Entropy
        entropy = domain_result.get('domain_entropy', 3.0)
        if entropy > 4.5:
            base_score -= 15
        elif entropy < 3.0:
            base_score += 5

        # Clamp
        return {'score': max(0, min(100, base_score))}

    def _check_domain_parking(self, domain: str) -> bool:
        """Simulate domain parking detection based on domain patterns."""
        parking_indicators = ['parked', 'forsale', 'buy-this', 'domain-for-sale']
        domain_lower = domain.lower()
        return any(ind in domain_lower for ind in parking_indicators)
