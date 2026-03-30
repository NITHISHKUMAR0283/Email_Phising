"""
Phase 1: URL Parsing & Normalization
=====================================
RFC 3986 compliant URL parsing with obfuscation detection.
"""

import re
from urllib.parse import urlparse, unquote, parse_qs


class URLParser:
    """Parse and normalize URLs, detecting encoding tricks and obfuscation."""

    # Dangerous protocols
    DANGEROUS_PROTOCOLS = {'javascript', 'data', 'file', 'vbscript'}
    AUTO_PHISHING_PROTOCOLS = {'javascript', 'vbscript'}

    # Non-standard ports that raise suspicion
    SUSPICIOUS_PORTS = {8080, 8888, 4444, 8443, 3000, 9090, 1337, 31337}

    def parse(self, url: str) -> dict:
        """Parse a URL into components with risk analysis."""
        result = {
            'original_url': url,
            'normalized_url': url,
            'risk_factors': [],
            'checks_performed': 0,
            'is_valid': True,
        }

        # Normalize encoding
        normalized = self._normalize_encoding(url)
        result['normalized_url'] = normalized
        result['checks_performed'] += 1

        # Detect double encoding
        double_encoded = self._detect_double_encoding(url)
        if double_encoded:
            result['risk_factors'].append({
                'factor': 'Double URL encoding detected',
                'severity': 'HIGH',
                'weight': 0.30
            })
        result['checks_performed'] += 1

        # Detect null byte injection
        if '%00' in url or '\x00' in url:
            result['risk_factors'].append({
                'factor': 'Null byte injection detected',
                'severity': 'HIGH',
                'weight': 0.30
            })
        result['checks_performed'] += 1

        # Detect HTML entity encoding
        if '&#' in url or '&amp;' in url:
            result['risk_factors'].append({
                'factor': 'HTML entity encoding in URL',
                'severity': 'MODERATE',
                'weight': 0.15
            })
        result['checks_performed'] += 1

        # Parse URL components
        try:
            parsed = urlparse(normalized)
        except Exception:
            result['is_valid'] = False
            result['protocol'] = 'unknown'
            result['domain'] = ''
            result['full_domain'] = ''
            result['path'] = ''
            result['query'] = ''
            result['query_params'] = {}
            result['fragment'] = ''
            result['port'] = None
            return result

        # Extract protocol
        protocol = (parsed.scheme or 'http').lower()
        result['protocol'] = protocol
        result['checks_performed'] += 1

        # Protocol validation
        if protocol in self.AUTO_PHISHING_PROTOCOLS:
            result['risk_factors'].append({
                'factor': f'Dangerous protocol: {protocol}:',
                'severity': 'CRITICAL',
                'weight': 0.50
            })
        elif protocol == 'data':
            result['risk_factors'].append({
                'factor': 'Data URI protocol - potential payload',
                'severity': 'HIGH',
                'weight': 0.40
            })
        elif protocol == 'file':
            result['risk_factors'].append({
                'factor': 'File protocol - local file access attempt',
                'severity': 'HIGH',
                'weight': 0.35
            })
        elif protocol == 'http':
            pass  # Handled in certificate analysis
        result['checks_performed'] += 1

        # Extract domain
        hostname = parsed.hostname or parsed.netloc or ''
        hostname = hostname.lower().strip('.')
        result['full_domain'] = hostname
        result['domain'] = hostname
        result['checks_performed'] += 1

        # Extract port
        port = parsed.port
        result['port'] = port
        if port and port in self.SUSPICIOUS_PORTS:
            result['risk_factors'].append({
                'factor': f'Non-standard port: {port}',
                'severity': 'MODERATE',
                'weight': 0.10
            })
        result['checks_performed'] += 1

        # Extract path
        result['path'] = parsed.path or '/'

        # Extract query
        result['query'] = parsed.query or ''
        result['query_params'] = parse_qs(parsed.query) if parsed.query else {}

        # Extract fragment
        result['fragment'] = parsed.fragment or ''

        # Count URL-encoded characters
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        result['encoding_count'] = encoded_count
        if encoded_count > 20:
            result['risk_factors'].append({
                'factor': f'Excessive URL encoding ({encoded_count} encoded chars)',
                'severity': 'MODERATE',
                'weight': 0.20
            })
        elif encoded_count > 10:
            result['risk_factors'].append({
                'factor': f'Elevated URL encoding ({encoded_count} encoded chars)',
                'severity': 'LOW',
                'weight': 0.10
            })
        result['checks_performed'] += 1

        # URL Length analysis
        url_length = len(url)
        result['url_length'] = url_length
        if url_length > 300:
            result['risk_factors'].append({
                'factor': f'Extremely long URL ({url_length} chars) - obfuscation attempt',
                'severity': 'MODERATE',
                'weight': 0.25
            })
        elif url_length > 150:
            result['risk_factors'].append({
                'factor': f'Long URL ({url_length} chars)',
                'severity': 'MODERATE',
                'weight': 0.15
            })
        elif url_length > 75:
            result['risk_factors'].append({
                'factor': f'Moderately long URL ({url_length} chars)',
                'severity': 'LOW',
                'weight': 0.08
            })
        elif url_length > 30:
            result['risk_factors'].append({
                'factor': f'Standard URL length ({url_length} chars)',
                'severity': 'LOW',
                'weight': 0.02
            })
        result['checks_performed'] += 1

        # Detect mixed case encoding
        mixed_case = re.findall(r'%[0-9A-Fa-f]{2}', url)
        if mixed_case:
            uppers = sum(1 for m in mixed_case if any(c.isupper() for c in m[1:]))
            lowers = sum(1 for m in mixed_case if any(c.islower() for c in m[1:]))
            if uppers > 0 and lowers > 0:
                result['risk_factors'].append({
                    'factor': 'Mixed-case URL encoding detected',
                    'severity': 'LOW',
                    'weight': 0.05
                })
        result['checks_performed'] += 1

        # Check for authentication in URL
        if parsed.username or parsed.password:
            result['risk_factors'].append({
                'factor': 'Credentials embedded in URL',
                'severity': 'HIGH',
                'weight': 0.30
            })
        result['checks_performed'] += 1

        # Check for @ symbol in URL (used to trick users)
        if '@' in (parsed.netloc or ''):
            result['risk_factors'].append({
                'factor': '@ symbol in URL - potential deceptive redirect',
                'severity': 'HIGH',
                'weight': 0.35
            })
        result['checks_performed'] += 1

        return result

    def _normalize_encoding(self, url: str) -> str:
        """Normalize URL encoding to standard form."""
        try:
            # Decode percent-encoding once
            decoded = unquote(url)
            return decoded
        except Exception:
            return url

    def _detect_double_encoding(self, url: str) -> bool:
        """Detect double URL encoding (%25XX patterns)."""
        return bool(re.search(r'%25[0-9A-Fa-f]{2}', url))
