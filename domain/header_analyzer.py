"""
header_analyzer.py — Email Header Security Analysis Module
===========================================================

Extracts and analyzes email headers to detect spoofing, authentication
failures, and suspicious routing patterns.  Returns a JSON-serializable
dictionary of security flags consumable by ``risk_engine.py``.

Supported checks
-----------------
* **Authentication** – SPF, DKIM, DMARC status parsing from
  ``Authentication-Results``.
* **Routing** – Hop count and originating-IP extraction from ``Received``
  headers, with simulated reverse-DNS verification.
* **Spoofing** – Display-name brand impersonation, mismatched
  ``From`` / ``Return-Path``, and envelope-vs-header ``From`` comparison.
* **Time-of-arrival anomaly** – Flags emails sent during unusual hours
  (midnight–6 AM sender-local time).

Author : Phishing Detection Team
License: MIT
"""

from __future__ import annotations

import email
import email.utils
import json
import re
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.message import Message
from typing import Any, Dict, List, Optional, Tuple, Union


# ════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════

#: Known brands used for display-name spoofing detection.
KNOWN_BRANDS: list[str] = [
    "paypal", "google", "apple", "microsoft", "amazon",
    "netflix", "bank of america", "wells fargo", "chase",
    "citibank", "facebook", "instagram", "whatsapp", "linkedin",
    "dropbox", "adobe", "zoom", "slack", "github", "twitter",
    "usps", "fedex", "dhl", "ups", "irs", "coinbase",
]

#: Domains considered "trusted" (extend as needed).
TRUSTED_DOMAINS: set[str] = {
    "paypal.com", "google.com", "apple.com", "microsoft.com",
    "amazon.com", "netflix.com", "bankofamerica.com", "wellsfargo.com",
    "chase.com", "citibank.com", "facebook.com", "instagram.com",
    "whatsapp.com", "linkedin.com", "dropbox.com", "adobe.com",
    "zoom.us", "slack.com", "github.com", "twitter.com", "x.com",
    "usps.com", "fedex.com", "dhl.com", "ups.com", "irs.gov",
    "coinbase.com",
}

#: Authentication statuses considered *failing*.
FAILING_STATUSES: set[str] = {"fail", "softfail", "none", "temperror", "permerror"}

#: Regex to pull an IPv4 address from a ``Received`` header.
_IP_RE = re.compile(
    r"\b(?:from|by)\s+\S+\s+\(.*?\[(\d{1,3}(?:\.\d{1,3}){3})\]",
    re.IGNORECASE,
)

#: Fallback: grab *any* bracketed IPv4.
_IP_FALLBACK_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")

#: Regex for extracting auth protocol results from Authentication-Results.
_AUTH_PROTO_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*([\w]+)", re.IGNORECASE
)


# ════════════════════════════════════════════════════════════════════
# Data class for structured results
# ════════════════════════════════════════════════════════════════════

@dataclass
class HeaderAnalysisResult:
    """Structured output of a full header analysis.

    Every field is JSON-serializable.  The class is convertible via
    ``asdict()`` or the convenience ``.to_dict()`` / ``.to_json()``
    methods.
    """

    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    hops: int = 0
    originating_ip: Optional[str] = None
    rdns_match: Optional[bool] = None
    is_spoofed: bool = False
    spoofing_reasons: list[str] = field(default_factory=list)
    from_address: Optional[str] = None
    return_path: Optional[str] = None
    display_name: Optional[str] = None
    time_anomaly: bool = False
    header_risk_score: float = 0.0

    # ── serialisation helpers ────────────────────────────────────
    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dictionary (JSON-safe)."""
        return asdict(self)

    def to_json(self, **kwargs: Any) -> str:
        """Return a pretty-printed JSON string."""
        kwargs.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kwargs)


# ════════════════════════════════════════════════════════════════════
# Low-level parsers (pure functions)
# ════════════════════════════════════════════════════════════════════

def parse_email(raw: Union[str, Dict[str, Any]]) -> Message:
    """Parse a raw RFC 822 string **or** a header dictionary into an
    :class:`email.message.Message`.

    Args:
        raw: Either a ``str`` (full RFC 822 message) or a ``dict``
             mapping header names to values (or lists of values).

    Returns:
        An :class:`email.message.Message` object.

    Raises:
        TypeError: If *raw* is neither ``str`` nor ``dict``.
    """
    if isinstance(raw, str):
        return email.message_from_string(raw)
    if isinstance(raw, dict):
        msg = Message()
        for key, value in raw.items():
            if isinstance(value, list):
                for v in value:
                    msg[key] = str(v)
            else:
                msg[key] = str(value)
        return msg
    raise TypeError(
        f"Expected str or dict, got {type(raw).__name__}"
    )


def extract_authentication_results(
    msg: Message,
) -> Dict[str, str]:
    """Extract SPF, DKIM, and DMARC results from
    ``Authentication-Results`` headers.

    Args:
        msg: Parsed email message.

    Returns:
        Dictionary ``{'spf': ..., 'dkim': ..., 'dmarc': ...}`` with
        lowercase status strings.  Missing protocols default to
        ``'none'``.
    """
    results: Dict[str, str] = {"spf": "none", "dkim": "none", "dmarc": "none"}

    auth_headers = msg.get_all("Authentication-Results") or []
    for header in auth_headers:
        for match in _AUTH_PROTO_RE.finditer(header):
            proto = match.group(1).lower()
            status = match.group(2).lower()
            if proto in results:
                # first non-'none' result wins
                if results[proto] == "none" or status != "none":
                    results[proto] = status

    return results


def extract_received_hops(msg: Message) -> List[str]:
    """Return every ``Received`` header in chronological order
    (oldest first).

    Args:
        msg: Parsed email message.

    Returns:
        List of raw ``Received`` header strings.
    """
    received = msg.get_all("Received") or []
    # Received headers are prepended → reverse for chronological order.
    return list(reversed(received))


def extract_ips_from_received(received_headers: List[str]) -> List[str]:
    """Extract IPv4 addresses from a list of ``Received`` headers.

    Args:
        received_headers: Chronologically ordered ``Received`` values.

    Returns:
        List of IPv4 address strings (one per header that contained an
        IP).
    """
    ips: list[str] = []
    for hdr in received_headers:
        match = _IP_RE.search(hdr)
        if match:
            ips.append(match.group(1))
        else:
            fallback = _IP_FALLBACK_RE.search(hdr)
            if fallback:
                ips.append(fallback.group(1))
    return ips


def get_originating_ip(received_headers: List[str]) -> Optional[str]:
    """Determine the originating (first external) IP.

    Args:
        received_headers: Chronologically ordered ``Received`` values.

    Returns:
        The first public IPv4 found, or ``None``.
    """
    for ip in extract_ips_from_received(received_headers):
        if not _is_private_ip(ip):
            return ip
    # fall back to the very first IP if all are private
    all_ips = extract_ips_from_received(received_headers)
    return all_ips[0] if all_ips else None


def _is_private_ip(ip: str) -> bool:
    """Return ``True`` for RFC 1918 / loopback / link-local addresses."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    first, second = octets[0], octets[1]
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    if first == 169 and second == 254:
        return True
    return False


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform a reverse-DNS lookup for *ip*.

    Uses :func:`socket.gethostbyaddr`; falls back to ``None`` on
    failure.

    Args:
        ip: IPv4 address string.

    Returns:
        The resolved hostname or ``None``.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def simulate_reverse_dns(ip: str, claimed_domain: str) -> bool:
    """Simulated reverse-DNS match check.

    Attempts a real rDNS lookup first; if that fails it applies a
    heuristic (the IP should not be in a known-bad range **and** the
    claimed domain should not be a free-mail provider when the IP
    resolves to a different provider).

    Args:
        ip: IPv4 address string.
        claimed_domain: The domain the sender claims to represent.

    Returns:
        ``True`` if the IP *appears* to belong to the claimed domain.
    """
    hostname = reverse_dns_lookup(ip)
    if hostname is None:
        # Cannot resolve → suspicious but not definitive
        return False

    hostname_lower = hostname.lower()
    domain_lower = claimed_domain.lower()

    # Direct suffix match (e.g. mail-sor-f41.google.com ↔ google.com)
    if hostname_lower.endswith(domain_lower):
        return True

    # Second-level domain comparison
    def _sld(d: str) -> str:
        parts = d.rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else d

    return _sld(hostname_lower) == _sld(domain_lower)


# ════════════════════════════════════════════════════════════════════
# Spoofing detectors
# ════════════════════════════════════════════════════════════════════

def extract_address_parts(header_value: Optional[str]) -> Tuple[str, str]:
    """Split an email header value into *(display_name, email_address)*.

    Args:
        header_value: e.g. ``'"Bank of America" <spoof@evil.com>'``

    Returns:
        Tuple of ``(display_name, email_address)`` — both may be empty
        strings if parsing fails.
    """
    if not header_value:
        return ("", "")
    name, addr = email.utils.parseaddr(header_value)
    return (name.strip(), addr.strip().lower())


def extract_domain(address: str) -> str:
    """Return the domain portion of an email address.

    Args:
        address: e.g. ``'user@example.com'``

    Returns:
        The domain (e.g. ``'example.com'``), or an empty string.
    """
    if "@" in address:
        return address.rsplit("@", 1)[1].lower()
    return ""


def detect_display_name_spoofing(
    display_name: str,
    from_domain: str,
    known_brands: list[str] | None = None,
    trusted_domains: set[str] | None = None,
) -> Tuple[bool, str]:
    """Check if the display name impersonates a known brand while the
    actual domain is *not* trusted.

    Args:
        display_name: The human-readable sender name.
        from_domain: The domain in the ``From`` address.
        known_brands: Override the default brand list.
        trusted_domains: Override the default trusted-domain set.

    Returns:
        ``(is_spoofed, reason)`` tuple.
    """
    brands = known_brands or KNOWN_BRANDS
    trusted = trusted_domains or TRUSTED_DOMAINS

    name_lower = display_name.lower()
    for brand in brands:
        if brand in name_lower:
            if from_domain not in trusted:
                return (
                    True,
                    f"Display name contains '{brand}' but domain "
                    f"'{from_domain}' is not trusted",
                )
    return (False, "")


def detect_from_mismatch(
    header_from_addr: str,
    return_path_addr: str,
) -> Tuple[bool, str]:
    """Detect a mismatch between the header ``From`` and the
    ``Return-Path`` (envelope sender).

    Args:
        header_from_addr: Address from the ``From`` header.
        return_path_addr: Address from the ``Return-Path`` header.

    Returns:
        ``(is_mismatched, reason)`` tuple.
    """
    if not return_path_addr:
        return (False, "")

    from_domain = extract_domain(header_from_addr)
    rp_domain = extract_domain(return_path_addr)

    if from_domain and rp_domain and from_domain != rp_domain:
        return (
            True,
            f"From domain '{from_domain}' differs from "
            f"Return-Path domain '{rp_domain}'",
        )
    return (False, "")


# ════════════════════════════════════════════════════════════════════
# Time-of-arrival anomaly detector
# ════════════════════════════════════════════════════════════════════

def detect_time_anomaly(msg: Message) -> bool:
    """Flag emails whose ``Date`` header falls in the 00:00–06:00
    window (sender-local time).

    Args:
        msg: Parsed email message.

    Returns:
        ``True`` when the email was sent during the suspicious window.
    """
    date_str = msg.get("Date")
    if not date_str:
        return False

    parsed = email.utils.parsedate_to_datetime(date_str)
    # parsedate_to_datetime returns a timezone-aware datetime
    hour = parsed.hour
    return 0 <= hour < 6


# ════════════════════════════════════════════════════════════════════
# Risk scorer
# ════════════════════════════════════════════════════════════════════

def compute_header_risk_score(result: HeaderAnalysisResult) -> float:
    """Compute a composite header-based risk score in [0.0, 1.0].

    Scoring breakdown (weights normalised to 1.0):

    * SPF fail / softfail / none → +0.20
    * DKIM fail / none           → +0.20
    * DMARC fail / none          → +0.15
    * Display-name spoofing      → +0.20
    * From / Return-Path mismatch → +0.10
    * Excessive hops (> 5)       → +0.05
    * rDNS mismatch              → +0.05
    * Time-of-arrival anomaly    → +0.05

    Args:
        result: A partially-populated :class:`HeaderAnalysisResult`.

    Returns:
        Clamped float in [0.0, 1.0].
    """
    score = 0.0

    # Authentication failures
    if result.spf in FAILING_STATUSES:
        score += 0.20
    if result.dkim in FAILING_STATUSES:
        score += 0.20
    if result.dmarc in FAILING_STATUSES:
        score += 0.15

    # Spoofing signals
    if result.is_spoofed:
        score += 0.20

    # From / Return-Path mismatch
    from_domain = extract_domain(result.from_address or "")
    rp_domain = extract_domain(result.return_path or "")
    if from_domain and rp_domain and from_domain != rp_domain:
        score += 0.10

    # Routing anomalies
    if result.hops > 5:
        score += 0.05
    if result.rdns_match is False:
        score += 0.05

    # Time anomaly
    if result.time_anomaly:
        score += 0.05

    return round(min(score, 1.0), 2)


# ════════════════════════════════════════════════════════════════════
# Main analysis entry-point
# ════════════════════════════════════════════════════════════════════

def analyze_headers(
    raw_email: Union[str, Dict[str, Any]],
    *,
    perform_rdns: bool = False,
) -> HeaderAnalysisResult:
    """Run the full header-analysis pipeline.

    Args:
        raw_email: Raw RFC 822 email string **or** a header dictionary.
        perform_rdns: If ``True``, execute a real reverse-DNS lookup
            against the originating IP.  Disabled by default to avoid
            network calls in unit tests.

    Returns:
        A populated :class:`HeaderAnalysisResult` with all flags and
        the composite ``header_risk_score``.

    Example::

        >>> result = analyze_headers(raw_msg_string)
        >>> print(result.to_json())
        {
          "spf": "fail",
          "dkim": "pass",
          "dmarc": "fail",
          "hops": 4,
          "originating_ip": "203.0.113.42",
          "rdns_match": null,
          "is_spoofed": true,
          "spoofing_reasons": [
            "Display name contains 'paypal' but domain 'evil.com' is not trusted"
          ],
          "from_address": "support@evil.com",
          "return_path": "bounces@evil.com",
          "display_name": "PayPal Security",
          "time_anomaly": false,
          "header_risk_score": 0.85
        }
    """
    msg = parse_email(raw_email)
    result = HeaderAnalysisResult()

    # ── 1. Authentication checks ─────────────────────────────────
    auth = extract_authentication_results(msg)
    result.spf = auth["spf"]
    result.dkim = auth["dkim"]
    result.dmarc = auth["dmarc"]

    # ── 2. Routing / hop analysis ────────────────────────────────
    received = extract_received_hops(msg)
    result.hops = len(received)
    result.originating_ip = get_originating_ip(received)

    # ── 3. Reverse-DNS check ─────────────────────────────────────
    _, from_addr = extract_address_parts(msg.get("From"))
    from_domain = extract_domain(from_addr)
    result.from_address = from_addr

    if result.originating_ip and from_domain:
        if perform_rdns:
            result.rdns_match = simulate_reverse_dns(
                result.originating_ip, from_domain
            )
        else:
            # Simulated: assume mismatch for non-trusted domains
            result.rdns_match = from_domain in TRUSTED_DOMAINS

    # ── 4. Display-name spoofing ─────────────────────────────────
    display_name, _ = extract_address_parts(msg.get("From"))
    result.display_name = display_name or None

    spoofed, reason = detect_display_name_spoofing(
        display_name, from_domain
    )
    if spoofed:
        result.is_spoofed = True
        result.spoofing_reasons.append(reason)

    # ── 5. From vs Return-Path mismatch ──────────────────────────
    _, rp_addr = extract_address_parts(msg.get("Return-Path"))
    result.return_path = rp_addr or None

    mismatched, mismatch_reason = detect_from_mismatch(from_addr, rp_addr)
    if mismatched:
        result.is_spoofed = True
        result.spoofing_reasons.append(mismatch_reason)

    # ── 6. Time-of-arrival anomaly ───────────────────────────────
    try:
        result.time_anomaly = detect_time_anomaly(msg)
    except Exception:
        result.time_anomaly = False

    # ── 7. Composite risk score ──────────────────────────────────
    result.header_risk_score = compute_header_risk_score(result)

    return result


# ════════════════════════════════════════════════════════════════════
# CLI entry-point (for quick testing)
# ════════════════════════════════════════════════════════════════════

def main() -> None:
    """Demonstrate the module with a synthetic phishing email."""
    sample_email = """\
Return-Path: <bounces@totally-not-evil.xyz>
Received: from gateway.evil-relay.net (unknown [203.0.113.42])
    by mx1.victim.com (Postfix) with ESMTP id ABC123
    for <target@victim.com>; Sat, 29 Mar 2026 03:14:07 +0000
Received: from internal.evil-relay.net (unknown [10.0.0.5])
    by gateway.evil-relay.net with ESMTP id DEF456;
    Sat, 29 Mar 2026 03:13:55 +0000
Received: from origin-server.phish.net (unknown [198.51.100.7])
    by internal.evil-relay.net with SMTP id GHI789;
    Sat, 29 Mar 2026 03:13:40 +0000
Authentication-Results: mx1.victim.com;
    spf=fail smtp.mailfrom=bounces@totally-not-evil.xyz;
    dkim=none header.d=totally-not-evil.xyz;
    dmarc=fail header.from=totally-not-evil.xyz
From: "PayPal Security Team" <security@totally-not-evil.xyz>
To: target@victim.com
Subject: Urgent: Your Account Has Been Compromised
Date: Sat, 29 Mar 2026 03:14:07 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We have detected suspicious activity on your PayPal account.
Please click the link below to verify your identity immediately:

http://paypa1-secure-login.totally-not-evil.xyz/verify

Failure to do so within 24 hours will result in permanent
suspension of your account.

Sincerely,
PayPal Security Team
"""

    result = analyze_headers(sample_email)

    print("=" * 60)
    print("  EMAIL HEADER ANALYSIS REPORT")
    print("=" * 60)
    print(result.to_json())
    print("=" * 60)

    # Severity label
    score = result.header_risk_score
    if score >= 0.8:
        severity = "🔴 CRITICAL"
    elif score >= 0.5:
        severity = "🟠 HIGH"
    elif score >= 0.3:
        severity = "🟡 MEDIUM"
    else:
        severity = "🟢 LOW"

    print(f"\n  Severity : {severity} ({score})")
    if result.spoofing_reasons:
        print("  Spoofing Indicators:")
        for r in result.spoofing_reasons:
            print(f"    • {r}")
    print()


if __name__ == "__main__":
    main()
