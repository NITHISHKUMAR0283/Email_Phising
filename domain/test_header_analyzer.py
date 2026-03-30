"""
test_header_analyzer.py — Comprehensive unit tests for header_analyzer.py
=========================================================================

Covers:
  • Authentication result parsing (SPF, DKIM, DMARC)
  • Hop counting & originating-IP extraction
  • Display-name spoofing detection
  • From / Return-Path mismatch
  • Time-of-arrival anomaly detection
  • Composite risk scoring edge cases
  • Full pipeline (analyze_headers) integration tests

Run with:  python -m pytest test_header_analyzer.py -v
"""

import pytest
from header_analyzer import (
    HeaderAnalysisResult,
    parse_email,
    extract_authentication_results,
    extract_received_hops,
    extract_ips_from_received,
    get_originating_ip,
    extract_address_parts,
    extract_domain,
    detect_display_name_spoofing,
    detect_from_mismatch,
    detect_time_anomaly,
    compute_header_risk_score,
    analyze_headers,
)


# ─── Fixtures ────────────────────────────────────────────────────

SAMPLE_CLEAN_EMAIL = """\
Return-Path: <noreply@google.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
    by mx.example.com with ESMTPS id abc123;
    Mon, 29 Mar 2026 10:30:00 +0000
Authentication-Results: mx.example.com;
    spf=pass smtp.mailfrom=noreply@google.com;
    dkim=pass header.d=google.com;
    dmarc=pass header.from=google.com
From: Google <noreply@google.com>
To: user@example.com
Subject: Your security alert
Date: Mon, 29 Mar 2026 10:30:00 +0000
Content-Type: text/plain

This is a legitimate email from Google.
"""

SAMPLE_PHISH_EMAIL = """\
Return-Path: <bounces@totally-not-evil.xyz>
Received: from relay3.evil.net (unknown [203.0.113.99])
    by mx1.victim.com with ESMTP id X1;
    Sat, 29 Mar 2026 02:45:00 +0000
Received: from relay2.evil.net (unknown [10.0.0.5])
    by relay3.evil.net with ESMTP id X2;
    Sat, 29 Mar 2026 02:44:50 +0000
Received: from relay1.evil.net (unknown [198.51.100.7])
    by relay2.evil.net with SMTP id X3;
    Sat, 29 Mar 2026 02:44:40 +0000
Authentication-Results: mx1.victim.com;
    spf=fail smtp.mailfrom=bounces@totally-not-evil.xyz;
    dkim=none header.d=totally-not-evil.xyz;
    dmarc=fail header.from=totally-not-evil.xyz
From: "PayPal Security" <security@totally-not-evil.xyz>
To: target@victim.com
Subject: Your account is compromised
Date: Sat, 29 Mar 2026 02:45:00 +0000
Content-Type: text/plain

Click here to verify: http://evil.link
"""

SAMPLE_SOFTFAIL_EMAIL = """\
Return-Path: <news@newsletter-service.com>
Received: from out.newsletter-service.com (out.newsletter-service.com [192.0.2.10])
    by mx.example.com with ESMTP id Y1;
    Tue, 30 Mar 2026 14:00:00 +0000
Authentication-Results: mx.example.com;
    spf=softfail smtp.mailfrom=news@newsletter-service.com;
    dkim=pass header.d=newsletter-service.com;
    dmarc=none header.from=newsletter-service.com
From: Daily News <news@newsletter-service.com>
To: reader@example.com
Subject: Your morning digest
Date: Tue, 30 Mar 2026 14:00:00 +0000
Content-Type: text/plain

Here's your daily news.
"""


# ─── Authentication Result Tests ─────────────────────────────────

class TestAuthenticationResults:
    def test_all_pass(self):
        msg = parse_email(SAMPLE_CLEAN_EMAIL)
        auth = extract_authentication_results(msg)
        assert auth["spf"] == "pass"
        assert auth["dkim"] == "pass"
        assert auth["dmarc"] == "pass"

    def test_all_fail(self):
        msg = parse_email(SAMPLE_PHISH_EMAIL)
        auth = extract_authentication_results(msg)
        assert auth["spf"] == "fail"
        assert auth["dkim"] == "none"
        assert auth["dmarc"] == "fail"

    def test_softfail(self):
        msg = parse_email(SAMPLE_SOFTFAIL_EMAIL)
        auth = extract_authentication_results(msg)
        assert auth["spf"] == "softfail"
        assert auth["dkim"] == "pass"
        assert auth["dmarc"] == "none"

    def test_missing_auth_header(self):
        msg = parse_email({"From": "test@test.com"})
        auth = extract_authentication_results(msg)
        assert auth == {"spf": "none", "dkim": "none", "dmarc": "none"}


# ─── Routing / Hop Tests ─────────────────────────────────────────

class TestRoutingAnalysis:
    def test_hop_count_clean(self):
        msg = parse_email(SAMPLE_CLEAN_EMAIL)
        hops = extract_received_hops(msg)
        assert len(hops) == 1

    def test_hop_count_phish(self):
        msg = parse_email(SAMPLE_PHISH_EMAIL)
        hops = extract_received_hops(msg)
        assert len(hops) == 3

    def test_ip_extraction(self):
        msg = parse_email(SAMPLE_PHISH_EMAIL)
        hops = extract_received_hops(msg)
        ips = extract_ips_from_received(hops)
        assert "198.51.100.7" in ips or "203.0.113.99" in ips

    def test_originating_ip_skips_private(self):
        msg = parse_email(SAMPLE_PHISH_EMAIL)
        hops = extract_received_hops(msg)
        ip = get_originating_ip(hops)
        # Should skip 10.0.0.5 and return a public IP
        assert ip is not None
        assert not ip.startswith("10.")

    def test_no_received_headers(self):
        msg = parse_email({"From": "x@y.com"})
        hops = extract_received_hops(msg)
        assert hops == []
        assert get_originating_ip(hops) is None


# ─── Address Parsing Tests ───────────────────────────────────────

class TestAddressParsing:
    def test_display_name_and_address(self):
        name, addr = extract_address_parts(
            '"Bank of America" <spoof@evil.com>'
        )
        assert name == "Bank of America"
        assert addr == "spoof@evil.com"

    def test_bare_address(self):
        name, addr = extract_address_parts("user@example.com")
        assert name == ""
        assert addr == "user@example.com"

    def test_none_input(self):
        name, addr = extract_address_parts(None)
        assert name == ""
        assert addr == ""

    def test_extract_domain(self):
        assert extract_domain("user@example.com") == "example.com"
        assert extract_domain("noatsign") == ""
        assert extract_domain("") == ""


# ─── Spoofing Detection Tests ───────────────────────────────────

class TestSpoofingDetection:
    def test_brand_spoof_detected(self):
        spoofed, reason = detect_display_name_spoofing(
            "PayPal Customer Service", "evil-domain.xyz"
        )
        assert spoofed is True
        assert "paypal" in reason.lower()

    def test_brand_trusted_not_flagged(self):
        spoofed, _ = detect_display_name_spoofing(
            "Google Alerts", "google.com"
        )
        assert spoofed is False

    def test_no_brand_not_flagged(self):
        spoofed, _ = detect_display_name_spoofing(
            "John Doe", "personal-domain.org"
        )
        assert spoofed is False

    def test_from_mismatch_detected(self):
        mismatch, reason = detect_from_mismatch(
            "ceo@company.com", "bounces@external-mailer.net"
        )
        assert mismatch is True
        assert "differs" in reason

    def test_from_match_ok(self):
        mismatch, _ = detect_from_mismatch(
            "noreply@company.com", "bounces@company.com"
        )
        assert mismatch is False

    def test_empty_return_path(self):
        mismatch, _ = detect_from_mismatch("a@b.com", "")
        assert mismatch is False


# ─── Time Anomaly Tests ─────────────────────────────────────────

class TestTimeAnomaly:
    def test_night_email_flagged(self):
        msg = parse_email(SAMPLE_PHISH_EMAIL)  # Date at 02:45 UTC
        assert detect_time_anomaly(msg) is True

    def test_day_email_ok(self):
        msg = parse_email(SAMPLE_CLEAN_EMAIL)  # Date at 10:30 UTC
        assert detect_time_anomaly(msg) is False

    def test_missing_date(self):
        msg = parse_email({"From": "x@y.com"})
        assert detect_time_anomaly(msg) is False


# ─── Risk Scoring Tests ─────────────────────────────────────────

class TestRiskScoring:
    def test_clean_email_low_score(self):
        result = HeaderAnalysisResult(
            spf="pass", dkim="pass", dmarc="pass",
            hops=1, is_spoofed=False,
        )
        score = compute_header_risk_score(result)
        assert score <= 0.1

    def test_full_failure_high_score(self):
        result = HeaderAnalysisResult(
            spf="fail", dkim="fail", dmarc="fail",
            hops=8, is_spoofed=True,
            from_address="a@evil.com",
            return_path="b@other.com",
            rdns_match=False,
            time_anomaly=True,
        )
        score = compute_header_risk_score(result)
        assert score >= 0.9

    def test_score_clamped_to_1(self):
        result = HeaderAnalysisResult(
            spf="fail", dkim="fail", dmarc="fail",
            hops=99, is_spoofed=True,
            from_address="a@evil.com",
            return_path="b@other.com",
            rdns_match=False,
            time_anomaly=True,
        )
        score = compute_header_risk_score(result)
        assert score <= 1.0


# ─── Full Pipeline Integration Tests ────────────────────────────

class TestAnalyzeHeaders:
    def test_clean_email_pipeline(self):
        result = analyze_headers(SAMPLE_CLEAN_EMAIL)
        assert result.spf == "pass"
        assert result.dkim == "pass"
        assert result.dmarc == "pass"
        assert result.is_spoofed is False
        assert result.header_risk_score < 0.3

    def test_phish_email_pipeline(self):
        result = analyze_headers(SAMPLE_PHISH_EMAIL)
        assert result.spf == "fail"
        assert result.dmarc == "fail"
        assert result.is_spoofed is True
        assert result.header_risk_score >= 0.7
        assert len(result.spoofing_reasons) > 0

    def test_dict_input(self):
        headers = {
            "From": '"Amazon" <fake@scam.ru>',
            "Return-Path": "<bounces@scam.ru>",
            "Authentication-Results": (
                "mx.test; spf=fail; dkim=none; dmarc=fail"
            ),
        }
        result = analyze_headers(headers)
        assert result.spf == "fail"
        assert result.is_spoofed is True

    def test_serialization(self):
        result = analyze_headers(SAMPLE_PHISH_EMAIL)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "spf" in d
        assert "header_risk_score" in d

        j = result.to_json()
        assert isinstance(j, str)
        import json
        parsed = json.loads(j)
        assert parsed["spf"] == result.spf

    def test_type_error_on_bad_input(self):
        with pytest.raises(TypeError):
            analyze_headers(12345)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
