"""
Unit tests for detection ensemble
"""
import pytest
from detection.ensemble import ensemble_detect

def test_phishing_high():
    email = "Urgent! Click this link to reset your password."
    url = "http://192.168.1.1/reset"
    headers = {"From": "attacker@evil.ru"}
    result = ensemble_detect(email, url, headers)
    assert result["is_phishing"] is True
    assert result["risk_score"] == "High"

def test_phishing_low():
    email = "Hello, your meeting is scheduled."
    url = "http://company.com/meeting"
    headers = {"From": "hr@company.com"}
    result = ensemble_detect(email, url, headers)
    assert result["is_phishing"] is False
    assert result["risk_score"] == "Low"
