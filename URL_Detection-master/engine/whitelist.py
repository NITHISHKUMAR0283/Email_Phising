"""
Phase 8: Whitelist & Trust Verification
=========================================
Tier 1 and Tier 2 whitelist matching with validation logic.
"""


class WhitelistChecker:
    """Verify URLs against trusted domain whitelists."""

    # Tier 1 - Absolute Trust (exact root domain match)
    TIER1_DOMAINS = {
        # Google
        'google.com', 'youtube.com', 'gmail.com', 'googleapis.com',
        'gstatic.com', 'googlevideo.com', 'google.co.uk', 'google.co.in',
        'google.co.jp', 'google.de', 'google.fr', 'google.es',
        'google.it', 'google.com.br', 'google.ca', 'google.com.au',
        # Microsoft
        'microsoft.com', 'office.com', 'office365.com', 'live.com',
        'outlook.com', 'windows.com', 'microsoftonline.com', 'bing.com',
        'azure.com', 'visualstudio.com', 'skype.com',
        # Apple
        'apple.com', 'icloud.com',
        # Amazon
        'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp',
        'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.in',
        'amazon.com.br', 'amazon.ca', 'amazon.com.au',
        # Meta
        'facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com',
        'messenger.com',
        # Other major
        'netflix.com', 'spotify.com', 'linkedin.com', 'twitter.com',
        'x.com', 'github.com', 'stackoverflow.com', 'reddit.com',
        'paypal.com', 'stripe.com', 'wikipedia.org', 'wikimedia.org',
        'yahoo.com', 'zoom.us', 'dropbox.com', 'adobe.com',
        'salesforce.com', 'slack.com',
    }

    # Tier 2 - Trusted Infrastructure
    TIER2_DOMAINS = {
        'cloudflare.com', 'cloudfront.net', 'amazonaws.com',
        'azurewebsites.net', 'googleapis.com', 'gstatic.com',
        'githubusercontent.com', 'vercel.app', 'netlify.app',
        'heroku.com', 'herokuapp.com', 'github.io', 'gitlab.io',
        'firebaseapp.com', 'web.app', 'pages.dev',
        'akamaized.net', 'fastly.net', 'edgekey.net',
    }

    # Google wildcard domains (google.*)
    GOOGLE_TLDS = {
        '.com', '.co.uk', '.co.in', '.co.jp', '.de', '.fr', '.es',
        '.it', '.com.br', '.ca', '.com.au', '.co.kr', '.co.nz',
        '.co.za', '.co.id', '.com.mx', '.com.ar', '.com.sg',
        '.com.hk', '.com.tw', '.com.tr', '.com.ua', '.com.eg',
        '.nl', '.be', '.at', '.ch', '.se', '.no', '.dk', '.fi',
        '.pl', '.pt', '.gr', '.ie', '.ru', '.com.ph',
    }

    def check(self, parsed: dict, context: dict) -> dict:
        """Check URL against whitelists."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'whitelisted': False,
            'whitelist_tier': None,
        }

        domain = parsed.get('full_domain', '')
        if not domain:
            return result

        # Extract root domain
        parts = domain.split('.')
        if len(parts) >= 2:
            root = '.'.join(parts[-2:])
        else:
            root = domain

        # Also check with second-level TLD
        root_sld = '.'.join(parts[-3:]) if len(parts) >= 3 else root

        # =================================================================
        # Tier 1 Check
        # =================================================================
        result['checks_performed'] += 1

        tier1_match = False
        # Exact match
        if root in self.TIER1_DOMAINS or root_sld in self.TIER1_DOMAINS:
            tier1_match = True

        # Google wildcard check
        if not tier1_match and parts[-2] == 'google' if len(parts) >= 2 else False:
            tld = '.' + '.'.join(parts[-1:])
            sld = '.' + '.'.join(parts[-2:])[len('google'):]
            if tld in self.GOOGLE_TLDS or sld in self.GOOGLE_TLDS:
                tier1_match = True

        if tier1_match:
            # --- Shortener Exception ---
            # Even if from a known platform, shorteners should not be 'Safe'
            from .redirect_analysis import RedirectAnalyzer
            if root in RedirectAnalyzer.KNOWN_SHORTENERS or root_sld in RedirectAnalyzer.KNOWN_SHORTENERS:
                return result # No discount for shorteners

            result['whitelisted'] = True
            result['whitelist_tier'] = 1
            result['risk_factors'].append({
                'factor': f'Tier 1 whitelisted domain: {root}',
                'severity': 'LOW',
                'weight': -0.50
            })
            return result

        # =================================================================
        # Tier 2 Check
        # =================================================================
        result['checks_performed'] += 1
        for trusted in self.TIER2_DOMAINS:
            if domain.endswith(trusted) or root == trusted:
                result['whitelisted'] = True
                result['whitelist_tier'] = 2
                result['risk_factors'].append({
                    'factor': f'Tier 2 trusted infrastructure: {trusted}',
                    'severity': 'LOW',
                    'weight': -0.30
                })
                return result

        return result
