"""
Phase 6: Certificate & Security Analysis
==========================================
Simulated SSL/TLS validation and certificate trust assessment.
"""

import hashlib


class CertificateAnalyzer:
    """Simulate SSL/TLS certificate analysis."""

    TRUSTED_CAS = [
        'DigiCert', "Let's Encrypt", 'GlobalSign', 'Comodo',
        'Sectigo', 'GeoTrust', 'Thawte', 'RapidSSL',
        'Amazon Trust Services', 'Google Trust Services',
        'Microsoft IT TLS CA', 'Baltimore CyberTrust',
    ]

    def analyze(self, parsed: dict) -> dict:
        """Run certificate and security analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'ssl_status': 'none',
            'certificate_age': 'unknown',
            'ca_name': 'Unknown',
            'ca_trusted': False,
        }

        protocol = parsed.get('protocol', 'http')
        domain = parsed.get('full_domain', '')

        # =================================================================
        # HTTPS Status
        # =================================================================
        result['checks_performed'] += 1
        if protocol == 'https':
            # Simulate certificate analysis based on domain characteristics
            cert_sim = self._simulate_certificate(domain)
            result['ssl_status'] = cert_sim['status']
            result['certificate_age'] = cert_sim['age']
            result['ca_name'] = cert_sim['ca']
            result['ca_trusted'] = cert_sim['ca_trusted']

            if cert_sim['status'] == 'valid':
                result['risk_factors'].append({
                    'factor': 'Valid HTTPS with trusted certificate',
                    'severity': 'LOW',
                    'weight': -0.08
                })
            elif cert_sim['status'] == 'self-signed':
                result['risk_factors'].append({
                    'factor': 'Self-signed SSL certificate',
                    'severity': 'HIGH',
                    'weight': 0.30
                })
            elif cert_sim['status'] == 'expired':
                result['risk_factors'].append({
                    'factor': 'Expired SSL certificate',
                    'severity': 'HIGH',
                    'weight': 0.35
                })
            elif cert_sim['status'] == 'invalid':
                result['risk_factors'].append({
                    'factor': 'Invalid SSL certificate (domain mismatch)',
                    'severity': 'HIGH',
                    'weight': 0.40
                })
        elif protocol == 'http':
            result['ssl_status'] = 'none'
            result['risk_factors'].append({
                'factor': 'No HTTPS - unencrypted connection',
                'severity': 'LOW',
                'weight': 0.12
            })
        result['checks_performed'] += 1

        # =================================================================
        # Certificate Authority Trust
        # =================================================================
        result['checks_performed'] += 1
        if protocol == 'https' and result['ssl_status'] == 'valid':
            if result['ca_trusted']:
                result['risk_factors'].append({
                    'factor': f'Trusted Certificate Authority: {result["ca_name"]}',
                    'severity': 'LOW',
                    'weight': -0.10
                })
            else:
                result['risk_factors'].append({
                    'factor': f'Unknown Certificate Authority: {result["ca_name"]}',
                    'severity': 'MODERATE',
                    'weight': 0.15
                })

        # =================================================================
        # Certificate Age
        # =================================================================
        result['checks_performed'] += 1
        if protocol == 'https' and result['certificate_age'] == '<24h':
            result['risk_factors'].append({
                'factor': 'Certificate issued less than 24 hours ago',
                'severity': 'MODERATE',
                'weight': 0.25
            })
        elif protocol == 'https' and result['certificate_age'] == '1-7d':
            result['risk_factors'].append({
                'factor': 'Certificate issued within last 7 days',
                'severity': 'LOW',
                'weight': 0.15
            })
        elif protocol == 'https' and result['certificate_age'] == '90d+':
            result['risk_factors'].append({
                'factor': 'Established certificate (>90 days)',
                'severity': 'LOW',
                'weight': -0.05
            })

        return result

    def _simulate_certificate(self, domain: str) -> dict:
        """
        Simulate certificate properties deterministically based on domain.
        Well-known domains get valid certs; suspicious domains get varied results.
        """
        # Well-known domains always have valid certs from trusted CAs
        well_known = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'youtube.com', 'netflix.com', 'paypal.com',
            'github.com', 'linkedin.com', 'twitter.com', 'reddit.com',
            'wikipedia.org', 'instagram.com', 'whatsapp.com', 'yahoo.com',
            'outlook.com', 'live.com', 'office.com', 'stripe.com',
            'spotify.com', 'cloudflare.com', 'stackoverflow.com',
        }

        # Check if root domain is well-known
        parts = domain.split('.')
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        for wd in well_known:
            if domain.endswith(wd) or root == wd:
                return {
                    'status': 'valid',
                    'age': '90d+',
                    'ca': 'DigiCert',
                    'ca_trusted': True,
                }

        # Hash-based simulation for other domains
        h = int(hashlib.md5(domain.encode()).hexdigest()[:8], 16)

        # Suspicious domain characteristics increase chance of bad certs
        from .tld_data import CRITICAL_RISK_TLDS, HIGH_RISK_TLDS
        tld = '.' + parts[-1] if parts else ''
        is_suspicious_tld = tld in CRITICAL_RISK_TLDS or tld in HIGH_RISK_TLDS
        has_numbers = any(c.isdigit() for c in parts[0]) if parts else False

        if is_suspicious_tld or has_numbers:
            # Higher chance of bad cert
            cert_roll = h % 10
            if cert_roll < 3:
                return {'status': 'self-signed', 'age': '<24h', 'ca': 'Self-Signed', 'ca_trusted': False}
            elif cert_roll < 5:
                return {'status': 'valid', 'age': '1-7d', 'ca': "Let's Encrypt", 'ca_trusted': True}
            elif cert_roll < 7:
                return {'status': 'valid', 'age': '<24h', 'ca': "Let's Encrypt", 'ca_trusted': True}
            else:
                return {'status': 'expired', 'age': '90d+', 'ca': 'Unknown CA', 'ca_trusted': False}
        else:
            # Normal domains mostly get valid certs
            cert_roll = h % 20
            if cert_roll < 12:
                ca_index = h % len(self.TRUSTED_CAS)
                return {'status': 'valid', 'age': '90d+', 'ca': self.TRUSTED_CAS[ca_index], 'ca_trusted': True}
            elif cert_roll < 16:
                return {'status': 'valid', 'age': '7-90d', 'ca': "Let's Encrypt", 'ca_trusted': True}
            elif cert_roll < 18:
                return {'status': 'valid', 'age': '1-7d', 'ca': "Let's Encrypt", 'ca_trusted': True}
            else:
                return {'status': 'self-signed', 'age': '1-7d', 'ca': 'Self-Signed', 'ca_trusted': False}
