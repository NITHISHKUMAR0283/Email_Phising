"""
Phase 5: Redirect & URL Shortener Analysis
============================================
Detection of URL shorteners and redirect chain simulation.
"""

import re


class RedirectAnalyzer:
    """Analyze URL for shortener usage and redirect patterns."""

    KNOWN_SHORTENERS = {
        'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 'ow.ly',
        't.co', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 's.id',
        'cutt.ly', 'shorturl.at', 'rb.gy', 'is.gd', 'v.gd',
        'tiny.cc', 'cli.gs', 'x.co', 'short.io', 'shor.by',
        'rebrand.ly', 'smarturl.it', 'mcaf.ee', 'db.tt',
        'qr.ae', 'amzn.to', 'youtu.be',  # brand shorteners
    }

    # Open redirect patterns in well-known services
    OPEN_REDIRECT_PATTERNS = [
        r'google\.com/url\?',
        r'facebook\.com/l\.php\?',
        r'youtube\.com/redirect\?',
        r'linkedin\.com/redir/',
        r'microsoft\.com/link\?',
    ]

    def analyze(self, parsed: dict) -> dict:
        """Analyze for shorteners and redirects."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'shortener_used': False,
            'redirect_detected': False,
            'shortener_name': None,
        }

        domain = parsed.get('full_domain', '')
        original_url = parsed.get('original_url', '')
        query = parsed.get('query', '')

        # =================================================================
        # URL Shortener Detection
        # =================================================================
        result['checks_performed'] += 1
        for shortener in self.KNOWN_SHORTENERS:
            if domain == shortener or domain.endswith('.' + shortener):
                result['shortener_used'] = True
                result['shortener_name'] = shortener
                result['risk_factors'].append({
                    'factor': f'URL shortener detected: {shortener}',
                    'severity': 'MODERATE',
                    'weight': 0.25
                })
                break

        # Also check if domain looks like a shortener (very short domain + short path)
        result['checks_performed'] += 1
        if not result['shortener_used']:
            domain_parts = domain.split('.')
            if len(domain_parts) == 2 and len(domain_parts[0]) <= 4:
                path = parsed.get('path', '/')
                if len(path) <= 10 and path != '/':
                    result['risk_factors'].append({
                        'factor': f'Possible unknown URL shortener: {domain}',
                        'severity': 'LOW',
                        'weight': 0.08
                    })

        # =================================================================
        # Open Redirect Detection
        # =================================================================
        result['checks_performed'] += 1
        for pattern in self.OPEN_REDIRECT_PATTERNS:
            if re.search(pattern, original_url, re.IGNORECASE):
                result['redirect_detected'] = True
                result['risk_factors'].append({
                    'factor': f'Open redirect via trusted service detected',
                    'severity': 'MODERATE',
                    'weight': 0.35
                })
                break

        # Check for redirect-like query parameters
        result['checks_performed'] += 1
        redirect_params = ['url', 'redirect', 'next', 'goto', 'dest', 'return', 'redir']
        query_params = parsed.get('query_params', {})
        for param in redirect_params:
            if param in query_params:
                values = query_params[param]
                for val in values:
                    if re.match(r'https?://', val, re.IGNORECASE):
                        result['redirect_detected'] = True
                        break

        # =================================================================
        # Redirect Chain Simulation
        # =================================================================
        result['checks_performed'] += 1
        if result['shortener_used']:
            # Simulate 1-2 redirects for known shorteners
            simulated_redirects = 2
            result['risk_factors'].append({
                'factor': f'Simulated redirect chain ({simulated_redirects} hops)',
                'severity': 'LOW',
                'weight': 0.10
            })

        return result
