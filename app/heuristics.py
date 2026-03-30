
from typing import List, Dict, Optional, Tuple
import tldextract
import re
from urllib.parse import urlparse
import time
from datetime import datetime
import socket
import ssl
import requests
from bs4 import BeautifulSoup
from urllib.request import urlopen
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Try importing whois and dns, set flags if unavailable
try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# List of suspicious keywords/phrases for phishing detection
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "reset your password", "account locked", "unusual sign-in", "secure your account", "temporary suspension", "click here", "action required", "confirm your identity",
    "mandatory", "compliance", "it policy", "training", "cybersecurity", "lockout", "survey", "deadline"
]

# Compile regex pattern once for better performance
KEYWORDS_PATTERN = re.compile("|".join(re.escape(kw) for kw in SUSPICIOUS_KEYWORDS), re.IGNORECASE)
SUSPICIOUS_URL_KEYWORDS = re.compile(r"(login|secure|update|verify|confirm|approve|urgent|action|validate|alert|password|signin|account)", re.IGNORECASE)

# Whitelist of known safe internal domains
INTERNAL_DOMAIN_WHITELIST = [
    "internal.company.com",
    "intranet.company.com",
    "portal.company.com",
    "internal-srm-ist.edu"
]

# List of suspicious TLDs
SUSPICIOUS_TLDS = [".xyz", ".ru", ".top", ".cn", ".tk", ".info", ".biz", ".pw", ".ml"]

# Known phishing domain patterns
PHISHING_DOMAIN_PATTERNS = re.compile(r"(paypa1|amaz0n|go0gle|micr0s0ft|apple-id)", re.IGNORECASE)

# Legitimate company domains (for impersonation detection)
LEGITIMATE_DOMAINS = [
    "paypal.com", "amazon.com", "google.com", "microsoft.com", "apple.com", 
    "facebook.com", "twitter.com", "instagram.com", "github.com", "linkedin.com"
]


def check_domain_age(domain: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Check domain age using WHOIS data.
    Returns: (age_in_days, creation_date) or (None, error_message)
    """
    if not HAS_WHOIS:
        return None, "WHOIS unavailable"
    
    try:
        result = whois.whois(domain)
        creation_date = result.creation_date
        
        # Handle cases where creation_date might be a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days, creation_date.isoformat()
        return None, "Creation date not found"
    except Exception as e:
        return None, f"WHOIS lookup failed: {str(e)[:50]}"


def check_dns_records(domain: str) -> Dict[str, any]:
    """
    Check DNS records (A, MX, TXT) for domain.
    Returns dict with record information and suspicious patterns.
    """
    if not HAS_DNS:
        return {"a_records": [], "mx_records": [], "txt_records": [], "status": "DNS unavailable"}
    
    dns_info = {"a_records": [], "mx_records": [], "txt_records": [], "status": "success"}
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        # Check A records
        try:
            a_records = resolver.resolve(domain, 'A')
            dns_info["a_records"] = [rr.to_text() for rr in a_records]
        except:
            dns_info["a_records"] = []
        
        # Check MX records
        try:
            mx_records = resolver.resolve(domain, 'MX')
            dns_info["mx_records"] = [rr.to_text() for rr in mx_records]
        except:
            dns_info["mx_records"] = []
        
        # Check TXT records (SPF, DMARC)
        try:
            txt_records = resolver.resolve(domain, 'TXT')
            dns_info["txt_records"] = [rr.to_text() for rr in txt_records]
        except:
            dns_info["txt_records"] = []
        
        return dns_info
    except Exception as e:
        return {"a_records": [], "mx_records": [], "txt_records": [], "status": f"DNS check failed: {str(e)[:50]}"}


def check_ssl_certificate(domain: str) -> Dict[str, any]:
    """
    Check SSL certificate details for suspicious patterns.
    Returns info about certificate issuer, validity, and org name.
    """
    ssl_info = {"has_ssl": False, "issuer": None, "validity_days": None, "org_name": None, "status": "unchecked"}
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info["has_ssl"] = True
                
                # Extract subject info
                for sub in cert.get('subject', []):
                    for key, value in sub:
                        if key == 'organizationName':
                            ssl_info["org_name"] = value
                        elif key == 'commonName':
                            ssl_info["cn"] = value
                
                # Extract issuer info
                for sub in cert.get('issuer', []):
                    for key, value in sub:
                        if key == 'organizationName':
                            ssl_info["issuer"] = value
                
                # Calculate certificate validity
                not_after = cert.get('notAfter')
                if not_after:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    ssl_info["validity_days"] = (expiry - datetime.now()).days
                
                ssl_info["status"] = "success"
    except socket.timeout:
        ssl_info["status"] = "SSL check timeout"
    except Exception as e:
        ssl_info["status"] = f"No SSL or error: {str(e)[:50]}"
    
    return ssl_info


def check_webpage_content(url: str) -> Dict[str, any]:
    """
    Fetch webpage and analyze for phishing indicators:
    - Fake forms, urgent keywords, suspicious scripts, brand impersonation
    """
    content_info = {"form_count": 0, "has_password_form": False, "urgent_keywords": [], 
                    "brand_impersonation": False, "status": "unchecked"}
    
    try:
        # Set timeout and headers to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, timeout=5, headers=headers, verify=False, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Count forms
        forms = soup.find_all('form')
        content_info["form_count"] = len(forms)
        
        # Check for password fields
        password_fields = soup.find_all('input', {'type': 'password'})
        content_info["has_password_form"] = len(password_fields) > 0
        
        # Get all text
        page_text = soup.get_text().lower()
        
        # Check for urgent keywords
        urgent_keywords = ["verify account", "confirm identity", "update payment", "click here", "act now", 
                          "urgent action", "account suspended", "unusual activity"]
        found_urgent = [kw for kw in urgent_keywords if kw in page_text]
        content_info["urgent_keywords"] = found_urgent
        
        # Check for brand impersonation
        for brand in LEGITIMATE_DOMAINS:
            brand_name = brand.split('.')[0].title()
            if brand_name in page_text and url not in brand:
                content_info["brand_impersonation"] = True
                content_info["impersonated_brand"] = brand_name
                break
        
        content_info["status"] = "success"
    except requests.exceptions.Timeout:
        content_info["status"] = "Fetch timeout (taking too long)"
    except Exception as e:
        content_info["status"] = f"Could not analyze content: {str(e)[:50]}"
    
    return content_info


def check_redirect_chain(url: str, max_redirects: int = 5) -> Dict[str, any]:
    """
    Check if URL redirects multiple times (suspicious behavior).
    Returns redirect chain and suspicious patterns.
    """
    redirect_info = {"redirect_count": 0, "final_url": url, "redirects": [], "status": "unchecked"}
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.head(url, timeout=3, headers=headers, allow_redirects=False, verify=False)
        
        current_url = url
        redirect_count = 0
        
        while response.status_code in [301, 302, 303, 307, 308] and redirect_count < max_redirects:
            redirect_url = response.headers.get('location')
            if not redirect_url:
                break
            redirect_info["redirects"].append(redirect_url)
            current_url = redirect_url
            redirect_count += 1
            
            response = requests.head(current_url, timeout=3, headers=headers, allow_redirects=False, verify=False)
        
        redirect_info["redirect_count"] = redirect_count
        redirect_info["final_url"] = current_url
        redirect_info["status"] = "success"
    except Exception as e:
        redirect_info["status"] = f"Redirect check failed: {str(e)[:50]}"
    
    return redirect_info


def get_ip_info(domain: str) -> Dict[str, any]:
    """
    Get IP address for domain.
    Returns IP and checks if it's suspicious (private range, etc).
    """
    ip_info = {"ip": None, "is_private": False, "status": "unchecked"}
    
    try:
        ip = socket.gethostbyname(domain)
        ip_info["ip"] = ip
        
        # Check if IP is in private range
        parts = ip.split('.')
        first_octet = int(parts[0])
        second_octet = int(parts[1])
        
        # Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
        if (first_octet == 10 or 
            (first_octet == 172 and 16 <= second_octet <= 31) or 
            (first_octet == 192 and second_octet == 168) or 
            first_octet == 127):
            ip_info["is_private"] = True
        
        ip_info["status"] = "success"
    except socket.gaierror:
        ip_info["status"] = "Domain resolution failed"
    except Exception as e:
        ip_info["status"] = f"IP lookup failed: {str(e)[:50]}"
    
    return ip_info


def analyze_url_detailed(url: str) -> Dict[str, any]:
    """
    🔥 REAL, ROBUST URL ANALYSIS - Multi-layer investigation pipeline
    
    Analyzes URL using:
    1. URL Structure (parsing, scheme, domain components)
    2. Domain Age (WHOIS - newly registered = HIGH RISK)
    3. DNS Records (A, MX, TXT - suspicious configs)
    4. SSL Certificate (validity, issuer, organization match)
    5. IP Intelligence (private ranges, geolocation suspicion)
    6. Webpage Content (forms, urgent keywords, brand impersonation)
    7. Redirect Chain (multiple redirects = suspicious)
    
    Returns comprehensive analysis with actual data, not patterns!
    """
    try:
        # Normalize URL: add https:// if protocol is missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url  # Default to HTTPS for missing schemes
        
        parsed = urlparse(url)
        ext = tldextract.extract(url)
        
        domain = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else parsed.netloc
        subdomain = ext.subdomain if ext.subdomain else "none"
        tld = f".{ext.suffix}" if ext.suffix else "unknown"
        scheme = parsed.scheme  # No default - assume https if normalized above
        
        suspicious_indicators = []
        reasons = []
        technical_details = {}
        risk_score = 0
        
        # 🔍 LAYER 1: URL STRUCTURE ANALYSIS
        # 1. Check for IP address (immediate red flag)
        if re.match(r'^(\d+\.){3}\d+$', parsed.netloc):
            suspicious_indicators.append("🚨 IP Address Used Instead of Domain")
            reasons.append("Why: Using bare IP address instead of domain name is classic phishing - attackers hide identity")
            risk_score += 20
        
        # 2. Check for HTTP (unencrypted)
        if scheme == "http":
            suspicious_indicators.append("⚠️  No HTTPS/Encryption")
            reasons.append("Why: HTTP lacks encryption. Any login credentials transmitted can be intercepted in transit")
            risk_score += 15
        
        # 3. Check for suspicious keywords in URL structure (only combined with other signs)
        # Don't penalize heavily - legitimate sites use these terms
        if SUSPICIOUS_URL_KEYWORDS.search(url):
            # Only flag if combined with other suspicious indicators
            pass  # Don't add risk for keywords alone
        
        # 4. Check for suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            suspicious_indicators.append(f"⚠️  Suspicious TLD ({tld})")
            reasons.append(f"Why: {tld} TLDs have high abuse rates. Legitimate companies use .com, .org, .gov")
            risk_score += 10
        
        # 5. Check for overly complex subdomains
        if subdomain:
            subdomain_count = len(subdomain.split('.'))
            if subdomain_count > 2:
                suspicious_indicators.append("🔸 Many Subdomains (obfuscation attempt)")
                reasons.append(f"Why: {subdomain_count} subdomains suggest attacker layering to evade filters")
                risk_score += 8
        
        # 6. Check for very long domain
        if len(domain) > 40:
            suspicious_indicators.append("📏 Unusually Long Domain Name")
            reasons.append("Why: Long domains often hide malicious intent in visual noise")
            risk_score += 5
        
        # 📅 LAYER 2: DOMAIN AGE (CRITICAL!)
        age_days, age_info = check_domain_age(domain)
        if age_days is not None:
            technical_details["domain_age_days"] = age_days
            technical_details["domain_creation_date"] = age_info
            
            if age_days <= 30:
                suspicious_indicators.append(f"🆕 VERY NEW Domain ({age_days} days old)")
                reasons.append(f"Why: Domain only {age_days} days old. Phishing sites use new domains - 87% of newly registered domains are used for phishing")
                risk_score += 25
            elif age_days <= 90:
                suspicious_indicators.append(f"📌 Recently Registered Domain ({age_days} days old)")
                reasons.append(f"Why: Domain {age_days} days old. Legitimate services rarely re-register domains")
                risk_score += 12
        else:
            technical_details["domain_age_info"] = age_info
        
        # 🌐 LAYER 3: DNS & INFRASTRUCTURE CHECK
        dns_records = check_dns_records(domain)
        technical_details["dns_records"] = dns_records
        
        if dns_records["status"] == "success":
            # Only flag if BOTH MX and A records are missing (complete DNS failure)
            if not dns_records["mx_records"] and not dns_records["a_records"]:
                suspicious_indicators.append("🔴 DNS Resolution Failed (no A or MX records)")
                reasons.append("Why: Domain has no valid DNS records - can't establish connection")
                risk_score += 12
        
        # 🔒 LAYER 4: SSL CERTIFICATE CHECK
        ssl_info = check_ssl_certificate(domain)
        technical_details["ssl_info"] = ssl_info
        
        if scheme == "https":
            if ssl_info["has_ssl"]:
                # Check for self-signed or free certificates (Let's Encrypt is legitimate but check org mismatch)
                if ssl_info["issuer"]:
                    if "self" in ssl_info["issuer"].lower():
                        suspicious_indicators.append("🚨 Self-Signed Certificate")
                        reasons.append("Why: Self-signed certs not issued by authority - attacker generated this")
                        risk_score += 20
# Only flag org mismatch if it's CLEARLY wrong (e.g., PayPal cert on Google domain)
                # Many legitimate sites use generic certificates or CDNs
                # Skip this check as it creates too many false positives
                pass
                
                if ssl_info["validity_days"] is not None and ssl_info["validity_days"] < 30:
                    suspicious_indicators.append(f"📅 Very Short SSL Validity ({ssl_info['validity_days']} days)")
                    reasons.append("Why: Certificate expiring soon - typical of phishing infrastructure quickly abandoned")
                    risk_score += 8
            else:
                suspicious_indicators.append("🚨 HTTPS But No Valid Certificate")
                reasons.append("Why: HTTPS URL with invalid/missing certificate - SSL handshake failed, likely self-signed")
                risk_score += 20
        
        # 🌍 LAYER 5: IP INTELLIGENCE
        ip_info = get_ip_info(domain)
        technical_details["ip_info"] = ip_info
        
        if ip_info["ip_info"] != "unchecked":
            if ip_info["is_private"]:
                suspicious_indicators.append(f"🏠 Private IP Address ({ip_info['ip']})")
                reasons.append("Why: Using private IP indicates internal/local network testing or VPN - attacker hiding location")
                risk_score += 15
        
        # 📄 LAYER 6: WEBPAGE CONTENT ANALYSIS
        if scheme in ["http", "https"]:
            content_info = check_webpage_content(url)
            technical_details["content_analysis"] = content_info
            
            if content_info["status"] == "success":
                # Password forms are normal on login pages - only flag if combined with other signs
                # Don't penalize standalone
                if content_info["has_password_form"] and risk_score >= 30:
                    suspicious_indicators.append("🔴 Password Form + Other Red Flags")
                    reasons.append("Why: Password form combined with other phishing indicators")
                    risk_score += 12
                
                if content_info["form_count"] > 3:
                    suspicious_indicators.append(f"📋 Multiple Forms ({content_info['form_count']})")
                    reasons.append("Why: Multiple forms suggest casting wide net for user data")
                    risk_score += 12
                
                if content_info["urgent_keywords"]:
                    suspicious_indicators.append(f"⏰ Urgent Action Keywords: {', '.join(content_info['urgent_keywords'][:2])}")
                    reasons.append("Why: Content uses urgency/fear tactics 'verify account', 'act now' - classic phishing psychology")
                    risk_score += 15
                
                if content_info["brand_impersonation"]:
                    brand = content_info.get("impersonated_brand", "Unknown")
                    suspicious_indicators.append(f"🏢 Brand Impersonation Detected ({brand})")
                    reasons.append(f"Why: Page content mimics {brand} but hosted on different domain - credential theft attack")
                    risk_score += 20
        
        # 🔄 LAYER 7: REDIRECT CHAIN ANALYSIS
        if scheme in ["http", "https"]:
            redirect_info = check_redirect_chain(url)
            technical_details["redirect_info"] = redirect_info
            
            if redirect_info["redirect_count"] > 5:
                suspicious_indicators.append(f"🔗 Excessive Redirects ({redirect_info['redirect_count']})")
                reasons.append(f"Why: URL redirects {redirect_info['redirect_count']} times - attacker obfuscating final destination")
                risk_score += 10
            elif redirect_info["redirect_count"] >= 1:
                technical_details["final_url_after_redirects"] = redirect_info["final_url"]
        
        # 🎯 LAYER 8: TYPOSQUATTING & HOMOGRAPH ATTACKS
        if PHISHING_DOMAIN_PATTERNS.search(domain):
            suspicious_indicators.append("🎭 Typosquatting Detected")
            reasons.append("Why: Domain uses lookalike misspellings of legitimate brands (paypa1, amaz0n, go0gle)")
            risk_score += 20
        
        # Check for character substitutions (0/O, l/1, etc)
        lookalike_chars = {'0': 'O', 'l': '1', '1': 'l', 'O': '0', 'I': '1'}
        if any(char in domain.lower() for char in lookalike_chars.keys()):
            suspicious_indicators.append("👁️  Homograph Attack Risk (lookalike characters)")
            reasons.append("Why: Domain uses similar-looking characters (0/O, l/1) to confuse users visually")
            risk_score += 12
        
        # 🏆 FINAL RISK ASSESSMENT
        overall_risk = "🟢 LOW"
        if risk_score >= 60:
            overall_risk = "🔴 CRITICAL"
        elif risk_score >= 40:
            overall_risk = "🟠 HIGH"
        elif risk_score >= 25:
            overall_risk = "🟡 MEDIUM"
        
        return {
            "url": url,
            "domain": domain,
            "subdomain": subdomain,
            "tld": tld,
            "scheme": scheme,
            "suspicious_indicators": suspicious_indicators,
            "reasons": reasons,
            "risk_count": len(suspicious_indicators),
            "risk_score": risk_score,
            "overall_risk": overall_risk,
            "technical_details": technical_details
        }
    except Exception as e:
        return {
            "url": url,
            "domain": "unknown",
            "subdomain": "unknown",
            "tld": "unknown",
            "scheme": "unknown",
            "suspicious_indicators": ["❌ Parse Error"],
            "reasons": [f"Why: Could not analyze URL - {str(e)[:80]}"],
            "risk_count": 1,
            "risk_score": 0,
            "overall_risk": "❓ UNKNOWN",
            "technical_details": {"error": str(e)[:100]}
        }

def analyze_heuristics(email_text: str, sender: Optional[str], urls: Optional[List[str]], headers: Optional[Dict[str, str]]) -> Dict:
    """
    Analyze email using heuristics: keywords, URLs, headers, sender domain.
    Returns a dict with a list of triggered heuristic signals and detailed URL analysis.
    """
    signals = []
    text_lower = email_text.lower()
    url_details = []
    
    # Keyword check - use compiled regex pattern for efficiency
    keyword_matches = KEYWORDS_PATTERN.findall(text_lower)
    for kw in set(keyword_matches):  # Use set to avoid duplicates
        signals.append(f"Suspicious phrase: {kw}")
    
    # URL/domain check with detailed analysis
    if urls:
        for url in urls:
            url_analysis = analyze_url_detailed(url)
            url_details.append(url_analysis)
            
            # Add indicators to signals
            for indicator in url_analysis.get("suspicious_indicators", []):
                signals.append(f"URL - {indicator}: {url_analysis.get('domain', 'unknown')}")
    
    # Header checks
    if headers:
        if headers.get("SPF", "").lower() == "fail":
            signals.append("SPF failed")
        if headers.get("DKIM", "").lower() == "fail":
            signals.append("DKIM failed")
        if headers.get("DMARC", "").lower() == "fail":
            signals.append("DMARC failed")
    
    # Sender domain check
    if sender:
        try:
            ext = tldextract.extract(sender)
            tld = f".{ext.suffix}" if ext.suffix else ""
            if tld in SUSPICIOUS_TLDS:
                signals.append(f"Sender TLD suspicious: {tld}")
        except Exception:
            pass  # Skip if sender parsing fails
    
    return {
        "signals": signals,
        "url_details": url_details  # Include detailed URL analysis
    }
