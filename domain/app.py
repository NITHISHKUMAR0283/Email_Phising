"""
app.py — Flask backend for the Phishing Header Analyzer UI
============================================================

Serves the frontend and exposes a /api/analyze endpoint that accepts
raw email headers and returns the full security analysis as JSON.

NOTE: This is a legacy Flask backend. The current frontend uses the FastAPI backend
located in app/main.py. This file is kept for reference and can be run standalone.
"""

from flask import Flask, render_template, request, jsonify
from .header_analyzer import analyze_headers
from .risk_engine import compute_risk, SEVERITY_LABELS

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the main analysis dashboard."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze raw email headers and return the risk report.

    Expects JSON body: {"raw_email": "...raw RFC 822 string..."}
    Optional fields:   {"nlp_score": 0.0, "link_score": 0.0, "visual_score": 0.0}
    """
    data = request.get_json(silent=True)
    if not data or "raw_email" not in data:
        return jsonify({"error": "Missing 'raw_email' field in request body"}), 400

    raw_email = data["raw_email"].strip()
    if not raw_email:
        return jsonify({"error": "Empty email content provided"}), 400

    try:
        # Run header analysis
        header_result = analyze_headers(raw_email)

        # Get optional sub-scores from other modules
        nlp_score = float(data.get("nlp_score", 0.0))
        link_score = float(data.get("link_score", 0.0))
        visual_score = float(data.get("visual_score", 0.0))

        # Compute unified risk
        risk_report = compute_risk(
            nlp_score=nlp_score,
            link_score=link_score,
            header_score=header_result.header_risk_score,
            visual_score=visual_score,
            details={"header_analysis": header_result.to_dict()},
        )

        # Build response
        response = {
            "success": True,
            "header_analysis": header_result.to_dict(),
            "risk_report": risk_report.to_dict(),
            "severity_meta": SEVERITY_LABELS.get(risk_report.severity, {}),
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500


@app.route("/api/sample", methods=["GET"])
def api_sample():
    """Return sample phishing and clean email strings for testing."""
    samples = {
        "phishing": """\
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
PayPal Security Team""",

        "clean": """\
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

This is a legitimate security alert from Google.""",

        "suspicious": """\
Return-Path: <newsletter@mail-promo.biz>
Received: from smtp-out1.mail-promo.biz (smtp-out1.mail-promo.biz [192.0.2.55])
    by mx.company.com with ESMTP id Z99;
    Sun, 29 Mar 2026 01:22:00 +0000
Received: from internal.mail-promo.biz (unknown [10.10.0.3])
    by smtp-out1.mail-promo.biz with ESMTP id Z98;
    Sun, 29 Mar 2026 01:21:50 +0000
Authentication-Results: mx.company.com;
    spf=softfail smtp.mailfrom=newsletter@mail-promo.biz;
    dkim=pass header.d=mail-promo.biz;
    dmarc=none header.from=mail-promo.biz
From: "Amazon Deals" <deals@mail-promo.biz>
To: shopper@company.com
Subject: Exclusive 90% Off - Act Now!
Date: Sun, 29 Mar 2026 01:22:00 +0000
Content-Type: text/html

<html><body><h1>HUGE SALE!</h1><a href="http://amaz0n-deals.mail-promo.biz">Click here</a></body></html>"""
    }
    return jsonify(samples)


if __name__ == "__main__":
    print("\n  🛡️  Phishing Header Analyzer is running!")
    print("  📍  Open http://127.0.0.1:5000 in your browser\n")
    app.run(debug=True, port=5000)
