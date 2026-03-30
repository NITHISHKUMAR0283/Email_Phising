"""
Phase 2: Domain Intelligence Analysis
=======================================
Domain entropy, age simulation, TLD risk, and structure analysis.
"""

import re
import hashlib
from math import log2
from collections import Counter
from .tld_data import get_tld_risk
from .homoglyphs import check_keyboard_walks


class DomainIntelligence:
    """Analyze domain characteristics for threat indicators."""

    # Known second-level TLDs
    SECOND_LEVEL_TLDS = {
        'co.uk', 'com.au', 'co.in', 'co.jp', 'co.kr', 'co.nz',
        'com.br', 'com.mx', 'com.ar', 'com.cn', 'com.sg', 'com.hk',
        'org.uk', 'net.au', 'ac.uk', 'gov.uk', 'edu.au', 'go.jp',
        'ne.jp', 'or.jp', 'co.za', 'com.tr', 'com.eg', 'com.pk',
        'co.id', 'com.my', 'com.ph', 'com.vn', 'com.tw', 'com.ua',
    }

    # CDN/cloud patterns that get special treatment
    CDN_PATTERNS = [
        'cloudfront.net', 'azurewebsites.net', 'herokuapp.com',
        'amazonaws.com', 'googleusercontent.com', 'cloudflare.com',
        'fastly.net', 'akamaized.net', 'edgekey.net',
        'vercel.app', 'netlify.app', 'github.io', 'gitlab.io',
        'firebaseapp.com', 'web.app', 'pages.dev',
    ]

    VOWELS = set('aeiou')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyz')

    def analyze(self, parsed: dict) -> dict:
        """Run domain intelligence analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
        }

        domain = parsed.get('full_domain', '')
        if not domain:
            return result

        # Extract root domain and TLD
        root_domain, tld, subdomains = self._extract_domain_parts(domain)
        result['root_domain'] = root_domain
        result['tld'] = tld
        result['subdomains'] = subdomains
        result['subdomain_count'] = len(subdomains)
        result['checks_performed'] += 1

        # Check if domain is an IP address
        is_ip, ip_type = self._check_ip_address(domain)
        result['is_ip_address'] = is_ip
        result['ip_type'] = ip_type
        if is_ip:
            weight = 0.50 if ip_type in ('decimal', 'octal', 'hex') else 0.40
            result['risk_factors'].append({
                'factor': f'IP address used as domain ({ip_type})',
                'severity': 'CRITICAL' if ip_type in ('decimal', 'octal', 'hex') else 'HIGH',
                'weight': weight
            })
        result['checks_performed'] += 1

        # Domain is CDN/cloud?
        result['is_cdn'] = self._is_cdn_domain(domain)

        # TLD Risk Analysis
        if tld and not is_ip:
            tld_risk_level, tld_weight = get_tld_risk(tld)
            result['tld_risk_level'] = tld_risk_level
            result['tld_risk_weight'] = tld_weight
            if tld_weight > 0:
                result['risk_factors'].append({
                    'factor': f'{tld_risk_level} risk TLD: {tld}',
                    'severity': 'HIGH' if tld_weight >= 0.25 else 'MODERATE',
                    'weight': tld_weight
                })
            elif tld_weight < 0:
                result['risk_factors'].append({
                    'factor': f'Trusted TLD: {tld}',
                    'severity': 'LOW',
                    'weight': tld_weight
                })
        else:
            result['tld_risk_level'] = 'NEUTRAL'
            result['tld_risk_weight'] = 0.0
        result['checks_performed'] += 1

        # Domain Entropy
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            entropy = self._shannon_entropy(domain_name)
            result['domain_entropy'] = round(entropy, 3)

            if entropy > 4.5:
                result['risk_factors'].append({
                    'factor': f'High domain entropy ({entropy:.2f}) - random string pattern',
                    'severity': 'HIGH',
                    'weight': 0.30
                })
            elif entropy > 3.5:
                result['risk_factors'].append({
                    'factor': f'Moderate domain entropy ({entropy:.2f})',
                    'severity': 'MODERATE',
                    'weight': 0.15
                })
            else:
                result['risk_factors'].append({
                    'factor': f'Natural domain entropy ({entropy:.2f})',
                    'severity': 'LOW',
                    'weight': -0.05
                })
        else:
            result['domain_entropy'] = 0.0
        result['checks_performed'] += 1

        # Consonant/Vowel ratio
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            cv_ratio = self._consonant_vowel_ratio(domain_name)
            result['cv_ratio'] = cv_ratio
            if cv_ratio is not None and (cv_ratio > 4.0 or cv_ratio < 0.25):
                result['risk_factors'].append({
                    'factor': f'Unnatural consonant/vowel ratio ({cv_ratio:.1f})',
                    'severity': 'MODERATE',
                    'weight': 0.10
                })
        result['checks_performed'] += 1

        # Keyboard walk detection
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            if check_keyboard_walks(domain_name):
                result['risk_factors'].append({
                    'factor': 'Keyboard walk pattern detected in domain',
                    'severity': 'MODERATE',
                    'weight': 0.20
                })
        result['checks_performed'] += 1

        # Subdomain count risk
        if not result['is_cdn']:
            sub_count = len(subdomains)
            if sub_count > 5:
                result['risk_factors'].append({
                    'factor': f'Excessive subdomain chaining ({sub_count} subdomains)',
                    'severity': 'HIGH',
                    'weight': 0.30
                })
            elif sub_count >= 4:
                result['risk_factors'].append({
                    'factor': f'Many subdomains ({sub_count})',
                    'severity': 'MODERATE',
                    'weight': 0.15
                })
            elif sub_count >= 2:
                result['risk_factors'].append({
                    'factor': f'Multiple subdomains ({sub_count})',
                    'severity': 'LOW',
                    'weight': 0.05
                })
        result['checks_performed'] += 1

        # Domain length
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            if len(domain_name) > 25:
                result['risk_factors'].append({
                    'factor': f'Long domain name ({len(domain_name)} chars)',
                    'severity': 'LOW',
                    'weight': 0.10
                })
        result['checks_performed'] += 1

        # Excessive hyphens
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            hyphen_count = domain_name.count('-')
            if hyphen_count > 2:
                result['risk_factors'].append({
                    'factor': f'Excessive hyphens in domain ({hyphen_count})',
                    'severity': 'MODERATE',
                    'weight': 0.15
                })
        result['checks_performed'] += 1

        # Numbers in unexpected places
        if root_domain and not is_ip:
            domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            if re.search(r'[a-z]+\d+[a-z]+', domain_name) or re.search(r'\d+[a-z]+\d+', domain_name):
                result['risk_factors'].append({
                    'factor': 'Numbers mixed with letters in domain (leet-speak pattern)',
                    'severity': 'MODERATE',
                    'weight': 0.10
                })
        result['checks_performed'] += 1

        # Domain age simulation (deterministic based on domain hash)
        age_estimate = self._simulate_domain_age(domain)
        result['domain_age_estimate'] = age_estimate['label']
        result['domain_age_days'] = age_estimate['days']
        if age_estimate['weight'] != 0:
            severity = 'HIGH' if age_estimate['weight'] >= 0.25 else (
                'MODERATE' if age_estimate['weight'] > 0 else 'LOW'
            )
            result['risk_factors'].append({
                'factor': f'Domain age estimate: {age_estimate["label"]}',
                'severity': severity,
                'weight': age_estimate['weight']
            })
        result['checks_performed'] += 1

        return result

    def _extract_domain_parts(self, domain: str) -> tuple:
        """Extract root domain, TLD, and subdomains from a domain string."""
        # Remove port if present
        domain = domain.split(':')[0]
        parts = domain.split('.')

        if len(parts) <= 1:
            return (domain, '', [])

        # Check for second-level TLD
        if len(parts) >= 3:
            possible_sld = '.'.join(parts[-2:])
            if possible_sld in self.SECOND_LEVEL_TLDS:
                tld = '.' + possible_sld
                root = '.'.join(parts[-3:])
                subdomains = parts[:-3]
                return (root, tld, subdomains)

        # Standard TLD
        tld = '.' + parts[-1]
        root = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        subdomains = parts[:-2] if len(parts) > 2 else []

        return (root, tld, subdomains)

    def _check_ip_address(self, domain: str) -> tuple:
        """Check if domain is an IP address (IPv4, IPv6, decimal, octal, hex)."""
        domain = domain.split(':')[0]  # remove port

        # Standard IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return (True, 'ipv4')

        # IPv6
        if domain.startswith('[') or ':' in domain:
            if re.match(r'^\[?[0-9a-fA-F:]+\]?$', domain):
                return (True, 'ipv6')

        # Decimal IP (e.g., 2130706433)
        if re.match(r'^\d{8,10}$', domain):
            return (True, 'decimal')

        # Octal IP (e.g., 0177.0.0.1)
        if re.match(r'^0\d+\.0?\d+\.0?\d+\.0?\d+$', domain):
            return (True, 'octal')

        # Hex IP (e.g., 0x7f.0x0.0x0.0x1)
        if re.match(r'^0x[0-9a-fA-F]+', domain):
            return (True, 'hex')

        return (False, None)

    def _is_cdn_domain(self, domain: str) -> bool:
        """Check if domain is a known CDN/cloud infrastructure domain."""
        for pattern in self.CDN_PATTERNS:
            if domain.endswith(pattern):
                return True
        return False

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq = Counter(text.lower())
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * log2(p)
        return entropy

    def _consonant_vowel_ratio(self, text: str) -> float:
        """Calculate consonant to vowel ratio."""
        text = text.lower()
        vowels = sum(1 for c in text if c in self.VOWELS)
        consonants = sum(1 for c in text if c in self.CONSONANTS)
        if vowels == 0:
            return float('inf') if consonants > 0 else None
        return consonants / vowels

    def _simulate_domain_age(self, domain: str) -> dict:
        """
        Simulate domain age using deterministic hashing.
        Known legitimate domains get old ages; unknown ones get hash-based ages.
        """
        # Well-known old domains
        old_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'youtube.com', 'wikipedia.org', 'twitter.com',
            'linkedin.com', 'github.com', 'netflix.com', 'paypal.com',
            'ebay.com', 'reddit.com', 'stackoverlfow.com', 'instagram.com',
            'whatsapp.com', 'yahoo.com', 'outlook.com', 'live.com',
            'office.com', 'icloud.com', 'spotify.com', 'stripe.com',
            'cloudflare.com', 'wordpress.com', 'mozilla.org',
        }

        root = domain.split(':')[0]
        parts = root.split('.')
        if len(parts) >= 2:
            # Check common second-level TLDs
            possible_sld = '.'.join(parts[-2:])
            check_domains = {possible_sld}
            if len(parts) >= 3:
                check_domains.add('.'.join(parts[-3:]))
        else:
            check_domains = {root}

        for d in check_domains:
            if d in old_domains:
                return {'days': 5000, 'label': '3y+', 'weight': -0.10}

        # Hash-based simulation for unknown domains
        h = int(hashlib.md5(root.encode()).hexdigest()[:8], 16)

        # Domains with suspicious characteristics get younger ages
        has_suspicious_tld = any(root.endswith(t) for t in ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.online', '.site'])
        has_hyphens = '-' in root
        has_numbers = any(c.isdigit() for c in root.split('.')[0])

        suspicion_count = sum([has_suspicious_tld, has_hyphens, has_numbers])

        if suspicion_count >= 2:
            # Likely suspicious - simulate young domain
            days = (h % 30) + 1
        elif suspicion_count == 1:
            days = (h % 180) + 7
        else:
            days = (h % 2000) + 30

        if days < 7:
            return {'days': days, 'label': '<7d', 'weight': 0.40}
        elif days < 30:
            return {'days': days, 'label': '7-30d', 'weight': 0.25}
        elif days < 90:
            return {'days': days, 'label': '30-90d', 'weight': 0.15}
        elif days < 365:
            return {'days': days, 'label': '90-365d', 'weight': 0.05}
        elif days < 1095:
            return {'days': days, 'label': '1-3y', 'weight': -0.05}
        else:
            return {'days': days, 'label': '3y+', 'weight': -0.10}
