"""
Phase 4: Structural & Behavioral Analysis
===========================================
IP detection, path/query analysis, URL encoding analysis.
"""

import re


class StructuralAnalyzer:
    """Analyze URL structural characteristics for threat indicators."""

    CRITICAL_PATH_KEYWORDS = [
        'login', 'signin', 'sign-in', 'account', 'verify', 'confirm',
        'validate', 'authenticate', 'billing', 'payment', 'secure',
        'update', 'suspended',
    ]

    HIGH_PATH_KEYWORDS = [
        'password', 'reset', 'recovery', 'unlock', 'restore',
        'urgent', 'alert', 'warning', 'action-required', 'action_required',
    ]

    MODERATE_PATH_KEYWORDS = [
        'customer', 'support', 'help', 'service',
        'download', 'attachment', 'document', 'invoice',
    ]

    REDIRECT_PARAMS = ['redirect', 'return_url', 'returnurl', 'next', 'goto', 'url', 'rurl', 'dest', 'destination', 'redir']

    def analyze(self, parsed: dict) -> dict:
        """Run structural analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'suspicious_keywords': [],
        }

        path = parsed.get('path', '/')
        query = parsed.get('query', '')
        query_params = parsed.get('query_params', {})

        # =================================================================
        # Path Keyword Analysis
        # =================================================================
        path_lower = path.lower()

        for keyword in self.CRITICAL_PATH_KEYWORDS:
            result['checks_performed'] += 1
            if keyword in path_lower:
                result['suspicious_keywords'].append(keyword)
                result['risk_factors'].append({
                    'factor': f'Critical path keyword: /{keyword}',
                    'severity': 'MODERATE',
                    'weight': 0.20
                })

        for keyword in self.HIGH_PATH_KEYWORDS:
            result['checks_performed'] += 1
            if keyword in path_lower:
                result['suspicious_keywords'].append(keyword)
                result['risk_factors'].append({
                    'factor': f'High-risk path keyword: /{keyword}',
                    'severity': 'MODERATE',
                    'weight': 0.15
                })

        for keyword in self.MODERATE_PATH_KEYWORDS:
            result['checks_performed'] += 1
            if keyword in path_lower:
                result['suspicious_keywords'].append(keyword)
                result['risk_factors'].append({
                    'factor': f'Suspicious path keyword: /{keyword}',
                    'severity': 'LOW',
                    'weight': 0.10
                })

        # =================================================================
        # Query Parameter Red Flags
        # =================================================================
        for param in self.REDIRECT_PARAMS:
            result['checks_performed'] += 1
            if param in query_params:
                values = query_params[param]
                for val in values:
                    if self._is_external_url(val):
                        weight = 0.25 if param in ('redirect', 'return_url', 'returnurl') else 0.20
                        result['risk_factors'].append({
                            'factor': f'Redirect parameter "{param}" points to external URL',
                            'severity': 'MODERATE',
                            'weight': weight
                        })
                        result['suspicious_keywords'].append(f'redirect:{param}')
                        break

        # Check for base64-encoded URL parameters
        result['checks_performed'] += 1
        for param, values in query_params.items():
            for val in values:
                if self._looks_like_base64(val) and len(val) > 20:
                    result['risk_factors'].append({
                        'factor': f'Base64-encoded value in parameter "{param}"',
                        'severity': 'MODERATE',
                        'weight': 0.15
                    })
                    break

        # =================================================================
        # Path depth analysis
        # =================================================================
        result['checks_performed'] += 1
        path_depth = len([p for p in path.split('/') if p])
        if path_depth > 8:
            result['risk_factors'].append({
                'factor': f'Deep URL path ({path_depth} levels)',
                'severity': 'LOW',
                'weight': 0.08
            })

        # =================================================================
        # File extension analysis
        # =================================================================
        result['checks_performed'] += 1
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.dll']
        for ext in suspicious_extensions:
            if path_lower.endswith(ext):
                result['risk_factors'].append({
                    'factor': f'Suspicious file extension: {ext}',
                    'severity': 'HIGH',
                    'weight': 0.25
                })
                result['suspicious_keywords'].append(f'extension:{ext}')
                break

        return result

    def _is_external_url(self, value: str) -> bool:
        """Check if a parameter value looks like an external URL."""
        return bool(re.match(r'https?://', value, re.IGNORECASE)) or value.startswith('//')

    def _looks_like_base64(self, value: str) -> bool:
        """Check if a string looks like base64 encoding."""
        if len(value) < 10:
            return False
        return bool(re.match(r'^[A-Za-z0-9+/]+=*$', value))
