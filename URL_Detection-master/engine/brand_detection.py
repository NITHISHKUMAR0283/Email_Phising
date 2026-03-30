"""
Phase 3: Brand Impersonation Detection
========================================
Multi-algorithm lookalike detection using Levenshtein, Jaro-Winkler,
Soundex/Metaphone, homograph detection, combosquatting, and subdomain spoofing.
"""

import Levenshtein
import jellyfish
from .brands import ALL_BRANDS, BRAND_CATEGORIES, COMBOSQUAT_KEYWORDS
from .homoglyphs import (
    normalize_homoglyphs, detect_homoglyphs,
    check_multi_char_tricks, VISUAL_LOOKALIKES
)


class BrandDetection:
    """Detect brand impersonation through multiple similarity algorithms."""

    def analyze(self, parsed: dict, domain_result: dict) -> dict:
        """Run brand impersonation analysis."""
        result = {
            'risk_factors': [],
            'checks_performed': 0,
            'potential_target': None,
            'similarity_score': None,
            'impersonation_type': 'none',
            'lookalike_detected': False,
        }

        domain = parsed.get('full_domain', '')
        if not domain:
            return result

        root_domain = domain_result.get('root_domain', domain)
        # Extract the registrable domain name (without TLD)
        domain_name = root_domain.split('.')[0] if '.' in root_domain else root_domain

        # Also get the full domain for subdomain spoofing checks
        full_domain = parsed.get('full_domain', '')

        best_match = None
        best_score = 0.0
        best_type = 'none'
        best_weight = 0.0

        # =================================================================
        # Algorithm 1: Homograph Detection (highest priority)
        # =================================================================
        homoglyphs = detect_homoglyphs(domain_name)
        result['checks_performed'] += 1

        if homoglyphs:
            normalized = normalize_homoglyphs(domain_name)
            # Check normalized name against brands
            for brand in ALL_BRANDS:
                if normalized == brand or Levenshtein.distance(normalized, brand) <= 1:
                    result['risk_factors'].append({
                        'factor': f'Homograph attack targeting "{brand}" - uses {homoglyphs[0]["script"]} characters',
                        'severity': 'CRITICAL',
                        'weight': 0.50
                    })
                    best_match = brand
                    best_score = 0.95
                    best_type = 'homograph'
                    best_weight = 0.50
                    break

            if not best_match and homoglyphs:
                result['risk_factors'].append({
                    'factor': f'Unicode homoglyph characters detected ({len(homoglyphs)} chars)',
                    'severity': 'HIGH',
                    'weight': 0.35
                })

        # =================================================================
        # Algorithm 2: Subdomain Spoofing (very high priority)
        # =================================================================
        result['checks_performed'] += 1
        subdomain_spoof = self._check_subdomain_spoofing(full_domain, root_domain)
        if subdomain_spoof:
            weight = 0.60
            result['risk_factors'].append({
                'factor': f'Subdomain spoofing of "{subdomain_spoof}" - legitimate domain used as subdomain of malicious root',
                'severity': 'CRITICAL',
                'weight': weight
            })
            if not best_match or weight > best_weight:
                best_match = subdomain_spoof
                best_score = 0.90
                best_type = 'subdomain_spoofing'
                best_weight = weight

        # =================================================================
        # Algorithm 3: Punycode Detection
        # =================================================================
        result['checks_performed'] += 1
        if domain_name.startswith('xn--') or 'xn--' in domain:
            result['risk_factors'].append({
                'factor': 'Punycode (internationalized) domain detected',
                'severity': 'HIGH',
                'weight': 0.45
            })
            # Check decoded form against brands
            try:
                decoded = domain_name.encode('ascii').decode('idna')
                for brand in ALL_BRANDS:
                    dist = Levenshtein.distance(decoded.lower(), brand)
                    if dist <= 2:
                        result['risk_factors'].append({
                            'factor': f'Punycode domain decodes to brand lookalike: "{decoded}" ~ "{brand}"',
                            'severity': 'CRITICAL',
                            'weight': 0.50
                        })
                        best_match = brand
                        best_score = 0.92
                        best_type = 'homograph'
                        best_weight = 0.50
                        break
            except (UnicodeError, UnicodeDecodeError):
                pass

        # Skip remaining brand algorithms if we already have a critical match
        if best_weight >= 0.50:
            result['potential_target'] = best_match
            result['similarity_score'] = best_score
            result['impersonation_type'] = best_type
            result['lookalike_detected'] = True
            return result

        # =================================================================
        # Algorithm 4: Exact + Levenshtein Distance
        # =================================================================
        for brand in ALL_BRANDS:
            result['checks_performed'] += 1

            # Apply visual leet-speak normalization for comparison
            normalized_domain = self._normalize_leet(domain_name)

            dist = Levenshtein.distance(normalized_domain, brand)

            if dist == 0:
                continue  # Exact match = legitimate (handled by whitelist)

            # --- Stricter constraints for very short brands ---
            # Brands with 3 or fewer characters must be exact match only
            if len(brand) <= 3:
                continue

            if dist <= 1:
                weight = 0.50
                if weight > best_weight:
                    best_match = brand
                    best_score = 1.0 - (dist / max(len(brand), len(domain_name)))
                    best_type = 'typosquatting'
                    best_weight = weight
                    result['risk_factors'].append({
                        'factor': f'Very close typosquat of "{brand}" (Levenshtein distance: {dist})',
                        'severity': 'CRITICAL',
                        'weight': weight
                    })
            elif dist <= 2:
                weight = 0.40
                if weight > best_weight:
                    best_match = brand
                    best_score = 1.0 - (dist / max(len(brand), len(domain_name)))
                    best_type = 'typosquatting'
                    best_weight = weight
                    result['risk_factors'].append({
                        'factor': f'Possible typosquat of "{brand}" (Levenshtein distance: {dist})',
                        'severity': 'HIGH',
                        'weight': weight
                    })
            elif dist <= 3 and len(brand) >= 7:
                weight = 0.25
                if weight > best_weight:
                    best_match = brand
                    best_score = 1.0 - (dist / max(len(brand), len(domain_name)))
                    best_type = 'typosquatting'
                    best_weight = weight
                    result['risk_factors'].append({
                        'factor': f'Suspicious similarity to "{brand}" (Levenshtein distance: {dist})',
                        'severity': 'MODERATE',
                        'weight': weight
                    })

        # =================================================================
        # Algorithm 5: Jaro-Winkler Similarity
        # =================================================================
        for brand in ALL_BRANDS:
            if len(brand) <= 3:
                continue  # Skip very short brands for fuzzy matching
            result['checks_performed'] += 1
            jw = jellyfish.jaro_winkler_similarity(domain_name, brand)

            if jw > 0.90 and best_weight < 0.45:
                best_match = brand
                best_score = jw
                best_type = 'typosquatting'
                best_weight = 0.45
                result['risk_factors'].append({
                    'factor': f'High Jaro-Winkler similarity to "{brand}" ({jw:.3f})',
                    'severity': 'CRITICAL',
                    'weight': 0.45
                })
            elif jw > 0.80 and best_weight < 0.30:
                best_match = brand
                best_score = jw
                best_type = 'typosquatting'
                best_weight = 0.30
                result['risk_factors'].append({
                    'factor': f'Moderate Jaro-Winkler similarity to "{brand}" ({jw:.3f})',
                    'severity': 'HIGH',
                    'weight': 0.30
                })

        # =================================================================
        # Algorithm 6: Phonetic Matching (Soundex/Metaphone)
        # =================================================================
        for brand in ALL_BRANDS:
            if len(brand) <= 3:
                continue
            result['checks_performed'] += 1
            try:
                domain_soundex = jellyfish.soundex(domain_name)
                brand_soundex = jellyfish.soundex(brand)
                domain_metaphone = jellyfish.metaphone(domain_name)
                brand_metaphone = jellyfish.metaphone(brand)

                if (domain_soundex == brand_soundex or domain_metaphone == brand_metaphone):
                    if domain_name != brand and best_weight < 0.35:
                        best_match = brand
                        best_score = 0.80
                        best_type = 'typosquatting'
                        best_weight = 0.35
                        result['risk_factors'].append({
                            'factor': f'Phonetic match with "{brand}" (Soundex: {domain_soundex})',
                            'severity': 'HIGH',
                            'weight': 0.35
                        })
            except Exception:
                pass

        # =================================================================
        # Algorithm 7: Combosquatting (ENHANCED - checks full URL segments)
        # =================================================================
        result['checks_performed'] += 1
        combo_result = self._check_combosquatting(domain_name, full_domain)
        if combo_result:
            weight = 0.40
            if weight > best_weight:
                best_match = combo_result['brand']
                best_score = 0.85
                best_type = 'combosquatting'
                best_weight = weight
            result['risk_factors'].append({
                'factor': f'Combosquatting: "{combo_result["brand"]}" + "{combo_result["keyword"]}"',
                'severity': 'HIGH',
                'weight': weight
            })

        # =================================================================
        # Algorithm 8: Multi-character visual tricks
        # =================================================================
        result['checks_performed'] += 1
        tricks = check_multi_char_tricks(domain_name)
        if tricks:
            # Check if the "corrected" version matches a brand
            corrected = domain_name
            for trick in tricks:
                corrected = corrected.replace(trick['sequence'], trick['looks_like'])
            for brand in ALL_BRANDS:
                if Levenshtein.distance(corrected, brand) <= 1:
                    weight = 0.40
                    if weight > best_weight:
                        best_match = brand
                        best_score = 0.85
                        best_type = 'typosquatting'
                        best_weight = weight
                    result['risk_factors'].append({
                        'factor': f'Visual trick "{tricks[0]["sequence"]}" -> "{tricks[0]["looks_like"]}" targeting "{brand}"',
                        'severity': 'HIGH',
                        'weight': weight
                    })
                    break

        # Set final results
        result['potential_target'] = best_match
        result['similarity_score'] = round(best_score, 3) if best_score else None
        result['impersonation_type'] = best_type if best_match else 'none'
        result['lookalike_detected'] = best_match is not None

        return result

    def _check_subdomain_spoofing(self, full_domain: str, root_domain: str) -> str:
        """
        Check if a legitimate brand appears as a subdomain of a malicious root domain.
        e.g., paypal.com.verify-account.tk → brand 'paypal' in subdomain, root is verify-account.tk
        Also checks hyphenated segments like: secure-google-login.evil.com
        """
        parts = full_domain.split('.')
        if len(parts) < 3:
            # For 2-part domains, still check if brand is embedded in hyphenated root
            root_name = root_domain.split('.')[0] if '.' in root_domain else root_domain
            if '-' in root_name:
                segments = root_name.split('-')
                for brand in ALL_BRANDS:
                    if len(brand) <= 3:
                        continue
                    if brand in segments:
                        return brand
            return None

        root_name = root_domain.split('.')[0] if '.' in root_domain else root_domain

        # Check if any brand appears in the subdomain portion
        subdomain_str = '.'.join(parts[:-2])  # everything except root.tld

        for brand in ALL_BRANDS:
            if len(brand) <= 3:
                continue
            # Brand in subdomain but NOT as root domain
            if brand in subdomain_str and brand != root_name:
                # Check: brand forms a domain-like pattern or appears as a segment
                if (f'{brand}.com' in subdomain_str or
                    f'{brand}.org' in subdomain_str or
                    brand in subdomain_str.split('.')):
                    return brand
                # Also check if brand is in a hyphenated subdomain segment
                for sub_part in subdomain_str.split('.'):
                    if brand in sub_part.split('-'):
                        return brand

        # Also check if brand is embedded in hyphenated root domain name
        if '-' in root_name:
            segments = root_name.split('-')
            for brand in ALL_BRANDS:
                if len(brand) <= 3:
                    continue
                if brand in segments:
                    # Brand in root hyphenated name is still spoofing
                    # e.g., verify-account-auth is not google, but google-login-verify IS
                    return None  # Don't flag root-hyphenated, combosquatting will catch it

        return None

    def _check_combosquatting(self, domain_name: str, full_domain: str) -> dict:
        """
        Detect combosquatting: <brand><separator><keyword> or <keyword><separator><brand>
        ENHANCED: Also checks across ALL segments of the full domain (subdomains + root).
        """
        # Check root domain name
        result = self._check_combo_in_string(domain_name)
        if result:
            return result

        # ENHANCED: Check across hyphenated segments of the ENTIRE domain
        all_segments = []
        for part in full_domain.split('.'):
            all_segments.extend(part.split('-'))

        # Check if any brand appears as a segment alongside keyword segments
        for brand in ALL_BRANDS:
            if len(brand) <= 3:
                continue
            if brand not in all_segments:
                continue

            remaining_segments = [s for s in all_segments if s != brand and s]
            for keyword in COMBOSQUAT_KEYWORDS:
                for seg in remaining_segments:
                    if keyword == seg or keyword in seg:
                        return {'brand': brand, 'keyword': keyword}

        return None

    def _check_combo_in_string(self, check_str: str) -> dict:
        """Check a single string for combosquatting patterns."""
        check_str = check_str.lower()

        for brand in ALL_BRANDS:
            if len(brand) <= 3:
                continue
            if brand not in check_str:
                continue
            if check_str == brand:
                continue  # Exact match is not combosquatting

            # Extract the non-brand part
            remainder = check_str.replace(brand, '', 1).strip('-_.')

            if not remainder:
                continue

            for keyword in COMBOSQUAT_KEYWORDS:
                if keyword in remainder:
                    return {'brand': brand, 'keyword': keyword}

        return None

    def _normalize_leet(self, text: str) -> str:
        """Normalize leet-speak substitutions."""
        leet_map = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
        }
        return ''.join(leet_map.get(c, c) for c in text.lower())
